/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/repository.go
 * Tier: Persistence Layer / Session Store
 *
 * Description: Data-access layer for session records. Creates sessions with hashed refresh
 *              tokens, performs the two-step rotation that moves the outgoing session into
 *              a grace state pointing at its successor, and serves the lookup, listing and
 *              revocation queries the service layer builds on.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/predicate"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sessionactivity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

// Sentinel errors for session lookup and refresh failures. Handlers match on
// these with errors.Is to choose a status code, so their identity is what
// matters, not their text.
var (
	// ErrSessionNotFound reports that no session matches the given ID or token.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionRevoked reports that the session was explicitly revoked.
	ErrSessionRevoked = errors.New("session has been revoked")
	// ErrSessionExpired reports that the session outlived its own lifetime.
	ErrSessionExpired = errors.New("session has expired")
	// ErrSessionCompromised reports detected refresh-token reuse. Sessions have
	// already been revoked per the tenant's policy by the time it is returned.
	ErrSessionCompromised = errors.New("session reuse detected; all sessions revoked for security")
	// ErrSessionNotOwned reports an attempt to act on another user's session.
	ErrSessionNotOwned = errors.New("unauthorized: session does not belong to user")
)

// Repository reads and writes session rows through the tenant-aware client factory.
type Repository struct {
	// factory resolves the ent client for a tenant and environment.
	factory *clientfactory.ClientFactory
}

// NewRepository constructs a session Repository over the given client factory.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// Factory exposes the underlying client factory so callers can reach sibling
// repositories without holding a second reference.
func (r *Repository) Factory() *clientfactory.ClientFactory {
	return r.factory
}

// HashRefreshToken returns the SHA-256 hex digest of a raw refresh token.
//
// Only the digest is stored, so a database leak does not yield usable refresh
// tokens. Lookups hash the presented token and match on the digest.
func HashRefreshToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// CreateSession records a new active session valid for ttl and returns it
// alongside the raw refresh token.
//
// The raw token is returned only here, because only its hash is persisted and it
// cannot be recovered afterwards. Passing an empty rawRefreshToken generates one.
func (r *Repository) CreateSession(ctx context.Context, tenantID, environment, userID, rawRefreshToken, ipAddress, userAgent, deviceFingerprintHmac, location string, ttl time.Duration) (*ent.Session, string, error) {
	rawToken := rawRefreshToken
	if rawToken == "" {
		rawToken = uuid.New().String() + uuid.New().String()
	}
	hash := HashRefreshToken(rawToken)
	id := idgen.New("ses")
	now := time.Now()
	expiresAt := now.Add(ttl)

	client := r.factory.GetClient(ctx, tenantID, environment)
	sess, err := client.Session.Create().
		SetID(id).
		SetUserID(userID).
		SetRefreshTokenHash(hash).
		SetStatus(session.StatusActive).
		SetIPAddress(ipAddress).
		SetUserAgent(userAgent).
		SetDeviceFingerprintHmac(deviceFingerprintHmac).
		SetLocation(location).
		SetLastActiveAt(now).
		SetExpiresAt(expiresAt).
		Save(ctx)
	if err != nil {
		return nil, "", err
	}

	// First use of this session at the application the request arrived through.
	// Recording it here rather than in each caller is what keeps a new sign-in
	// path from silently omitting it. The error is dropped on purpose:
	// per-application activity is reporting detail, and failing a sign-in over it
	// would trade a working login for a missing timestamp.
	_ = sessionactivity.Touch(ctx, client, sess.ID)

	return sess, rawToken, nil
}

// GetSessionByTokenHash looks up a session by refresh-token digest, returning
// ErrSessionNotFound when nothing matches.
//
// The query is deliberately not filtered by status: the caller must see revoked
// and grace-state rows to distinguish a legitimate refresh from token reuse.
func (r *Repository) GetSessionByTokenHash(ctx context.Context, hash string) (*ent.Session, error) {
	sess, err := r.factory.GetClient(ctx, "", "").Session.Query().
		Where(session.RefreshTokenHash(hash)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return sess, nil
}

// GetSessionByID loads a session by its identifier, returning ErrSessionNotFound
// when it does not exist.
func (r *Repository) GetSessionByID(ctx context.Context, sessionID string) (*ent.Session, error) {
	sess, err := r.factory.GetClient(ctx, "", "").Session.Get(ctx, sessionID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return sess, nil
}

// RotateSession issues a successor session valid for ttl and moves the outgoing
// one into the grace state for the duration of grace. It returns the new session
// and its raw refresh token.
//
// The successor is created before the old row is updated, so a failure part-way
// leaves the caller's existing token working rather than stranding the session
// with no usable successor. The old row records SupersededBySessionID, which is
// how a refresh arriving inside the grace window finds the session to answer for.
func (r *Repository) RotateSession(ctx context.Context, tenantID, environment, oldSessionID, newRawToken string, grace, ttl time.Duration) (*ent.Session, string, error) {
	client := r.factory.GetClient(ctx, tenantID, environment)
	oldSess, err := client.Session.Get(ctx, oldSessionID)
	if err != nil {
		return nil, "", err
	}

	newSess, newRaw, err := r.CreateSession(ctx, tenantID, environment, oldSess.UserID, newRawToken, oldSess.IPAddress, oldSess.UserAgent, oldSess.DeviceFingerprintHmac, oldSess.Location, ttl)
	if err != nil {
		return nil, "", err
	}

	graceExpiresAt := time.Now().Add(grace)
	_, err = client.Session.UpdateOneID(oldSessionID).
		SetStatus(session.StatusRotatedGrace).
		SetGraceExpiresAt(graceExpiresAt).
		SetSupersededBySessionID(newSess.ID).
		Save(ctx)
	if err != nil {
		return nil, "", err
	}

	// Per-application activity follows the successor. CreateSession has already
	// recorded this refresh against the new row, so this only moves the pairings
	// the outgoing session accumulated at other applications; the collision on
	// the current one is resolved in favour of the earlier first_seen_at. The
	// error is dropped for the same reason as at sign-in: the caller's tokens have
	// already rotated, and failing here would revoke a session that is now valid
	// over a reporting timestamp.
	_ = sessionactivity.CarryForward(ctx, client, oldSessionID, newSess.ID)

	return newSess, newRaw, nil
}

// RevokeSession marks a single session revoked, ending its ability to refresh.
func (r *Repository) RevokeSession(ctx context.Context, sessionID string) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.Session.UpdateOneID(sessionID).
		SetStatus(session.StatusRevoked).
		Exec(ctx)
}

// RevokeAllUserSessions revokes every non-revoked session for userID, optionally
// sparing exceptSessionID, and returns the number of rows changed.
func (r *Repository) RevokeAllUserSessions(ctx context.Context, userID string, exceptSessionID string) (int, error) {
	client := r.factory.GetClient(ctx, "", "")
	pred := session.UserID(userID)
	if exceptSessionID != "" {
		pred = session.And(pred, session.IDNEQ(exceptSessionID))
	}

	return client.Session.Update().
		Where(pred, session.StatusNEQ(session.StatusRevoked)).
		SetStatus(session.StatusRevoked).
		Save(ctx)
}

// GetUserActiveSessions returns the user's unrevoked, unexpired sessions, most
// recently active first.
func (r *Repository) GetUserActiveSessions(ctx context.Context, userID string) ([]*ent.Session, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.Session.Query().
		Where(
			session.UserID(userID),
			session.StatusNEQ(session.StatusRevoked),
			session.ExpiresAtGT(time.Now()),
		).
		Order(ent.Desc(session.FieldLastActiveAt)).
		All(ctx)
}

// PurgeExpiredSessions deletes session rows that can no longer authenticate
// anything and returns how many were removed. It requires a context carrying a
// privacy bypass, because the sweep spans every tenant.
//
// The two cutoffs separate rows kept for different reasons. A superseded row —
// one a refresh replaced — survives its grace window only so that a replay of
// its token is recognised as reuse rather than as an unknown credential, and
// supersededBefore bounds how long that recognition lasts. A row that aged out
// or was revoked also carries the sign-in history a user reads back from the
// session list, so terminalBefore is normally the longer of the two. Superseded
// rows are the higher-volume class by a wide margin: one is created per refresh,
// where the others need a sign-out or an expiry.
//
// Deletion is batched because a single unbounded DELETE against the largest
// table in the schema holds locks and extends the write-ahead log for as long as
// it runs — on a deployment's first sweep, that is the incident the sweep exists
// to prevent. Batches are selected in ID order so that two servers sweeping at
// once take row locks in the same sequence rather than deadlocking against each
// other.
func (r *Repository) PurgeExpiredSessions(ctx context.Context, supersededBefore, terminalBefore time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		return 0, fmt.Errorf("session purge: batch size must be positive, got %d", batchSize)
	}

	client := r.factory.GetClient(ctx, "", "")
	total := 0

	passes := []struct {
		name string
		pred predicate.Session
	}{
		{
			name: "superseded",
			pred: session.And(
				session.StatusEQ(session.StatusRotatedGrace),
				session.GraceExpiresAtLT(supersededBefore),
			),
		},
		{
			name: "terminal",
			pred: session.ExpiresAtLT(terminalBefore),
		},
	}

	for _, pass := range passes {
		for {
			if err := ctx.Err(); err != nil {
				return total, err
			}

			ids, err := client.Session.Query().
				Where(pass.pred).
				Order(ent.Asc(session.FieldID)).
				Limit(batchSize).
				IDs(ctx)
			if err != nil {
				return total, fmt.Errorf("selecting %s sessions to purge: %w", pass.name, err)
			}
			if len(ids) == 0 {
				break
			}

			removed, err := client.Session.Delete().
				Where(session.IDIn(ids...)).
				Exec(ctx)
			if err != nil {
				return total, fmt.Errorf("deleting %s sessions: %w", pass.name, err)
			}
			total += removed

			// A batch that selected rows but removed none means something outside this
			// predicate is holding them — another server that swept first, or a
			// constraint refusing the delete. Either way, re-selecting the same rows
			// would spin, and the next sweep can revisit them.
			if removed == 0 || len(ids) < batchSize {
				break
			}
		}
	}

	return total, nil
}
