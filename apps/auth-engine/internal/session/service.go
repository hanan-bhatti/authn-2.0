/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/service.go
 * Tier: Session Management Layer
 *
 * Description: Orchestration for refresh-token rotation and session lifecycle. Rotates a
 *              presented refresh token into a fresh token pair, honours a short grace
 *              window so concurrent in-flight refreshes are not all logged out, detects
 *              token reuse and applies the tenant's compromise policy, and serves session
 *              listing and revocation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/accountstatus"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// WebhookDispatcher publishes session lifecycle events to tenant webhooks.
type WebhookDispatcher interface {
	// Dispatch queues an event for delivery. It must not block the caller.
	//
	// environment is the environment the event originated in, and decides which
	// of the tenant's endpoints receive it.
	Dispatch(tenantID, environment, eventType string, data map[string]interface{})
}

// AccessTokenTTLResolver supplies the access-token lifetime a tenant has chosen.
//
// It is an interface so this package does not depend on the settings cache, and so
// tests can fix a lifetime without a database. authcookie.Writer satisfies it.
type AccessTokenTTLResolver interface {
	// AccessTokenTTL returns the lifetime for one of the tenant's environments,
	// already bounded by the deployment's ceiling. It does not fail: this is called
	// on the refresh path, where an error would end a live session, so
	// implementations fall back to the deployment default.
	AccessTokenTTL(ctx context.Context, tenantID, environment string) time.Duration
}

// Service implements session-management domain logic on top of Repository.
type Service struct {
	// repo provides session persistence and the ent client factory.
	repo *Repository
	// cfg supplies token lifetimes, the grace window and the signing key.
	cfg *config.Config
	// webhooks publishes revocations. May be nil, which disables emission; see emit.
	webhooks WebhookDispatcher
	// accessTTL supplies the tenant's chosen access-token lifetime. May be nil, in
	// which case every tenant gets the deployment default; see accessTokenTTL.
	accessTTL AccessTokenTTLResolver
}

// NewService constructs a session Service bound to repo and cfg.
func NewService(repo *Repository, cfg *config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
}

// WithWebhooks attaches the dispatcher that publishes revocation events, and
// returns the service for chaining.
//
// A separate method rather than a constructor parameter, so the tests that build
// this service need no webhook engine standing behind them.
func (s *Service) WithWebhooks(d WebhookDispatcher) *Service {
	s.webhooks = d
	return s
}

// WithAccessTokenTTLResolver points token issuance at the tenant's configured
// access-token lifetime and returns the service for chaining.
//
// Optional for the same reason as the webhook dispatcher: a test refreshing a
// session wants the deployment default, not a settings cache.
func (s *Service) WithAccessTokenTTLResolver(r AccessTokenTTLResolver) *Service {
	s.accessTTL = r
	return s
}

// accessTokenTTL returns how long an access token issued for tenantID in
// environment stays valid, capped for the test environment.
//
// A refreshed token gets the tenant's current lifetime rather than the one in
// force when the session opened, so shortening the setting takes effect on the
// next refresh instead of waiting out every session already running.
func (s *Service) accessTokenTTL(ctx context.Context, tenantID, environment string) time.Duration {
	if s.accessTTL != nil {
		return s.accessTTL.AccessTokenTTL(ctx, tenantID, environment)
	}
	if s.cfg == nil {
		return 0
	}
	return s.cfg.AccessTokenTTLFor(environment)
}

// emit queues a webhook event, doing nothing when no dispatcher is attached.
//
// A blank tenant is also dropped: an event has no endpoints to route to without
// one, and unlike the account-lifecycle paths the tenant here comes from the
// request rather than from a loaded row.
func (s *Service) emit(tenantID, environment, eventType string, data map[string]interface{}) {
	if s.webhooks == nil || tenantID == "" {
		return
	}
	s.webhooks.Dispatch(tenantID, environment, eventType, data)
}

// emitSessionRevoked publishes session.revoked, resolving the tenant and
// environment from the account the sessions belonged to.
//
// The revocation endpoints authorise on the bearer token's subject and so are
// reached with a user ID and nothing else, which is why the account is loaded
// here. data carries the fields that vary by call site; user_id is filled in.
//
// An account that cannot be resolved is skipped: the event has no tenant to
// route by, and the revocation it would report has already happened.
func (s *Service) emitSessionRevoked(ctx context.Context, userID string, data map[string]interface{}) {
	if s.webhooks == nil {
		return
	}

	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return
	}

	data["user_id"] = userID
	s.emit(u.TenantID, string(u.Environment), "session.revoked", data)
}

// SessionResponse is a session as presented to clients.
type SessionResponse struct {
	// ID is the session identifier, used to target a revocation.
	ID string `json:"id"`
	// Device is the browser, OS and form factor parsed from the user agent.
	Device DeviceInfo `json:"device"`
	// IPAddress is the client address recorded when the session was created.
	IPAddress string `json:"ip_address"`
	// Location is the coarse geographic label recorded for the session.
	Location string `json:"location"`
	// LastActiveAt is the RFC 3339 timestamp of the session's most recent activity.
	// A session stamps this when it is issued and every refresh issues a successor
	// row, so its resolution is the refresh cadence — one access-token lifetime —
	// rather than the individual request. Per-application activity is recorded
	// separately, at request granularity, by internal/sessionactivity.
	LastActiveAt string `json:"last_active_at,omitempty"`
	// CreatedAt is the RFC 3339 creation timestamp.
	CreatedAt string `json:"created_at"`
	// IsCurrent marks the session the request itself was made with.
	IsCurrent bool `json:"is_current"`
}

// SessionTokenPairResponse is the result of a token refresh.
type SessionTokenPairResponse struct {
	// AccessToken is the newly issued bearer JWT.
	AccessToken string `json:"access_token"`
	// RefreshToken is the new opaque refresh token. It is empty on a grace-window
	// replay, which must not hand out a second copy of the rotated secret.
	RefreshToken string `json:"refresh_token"`
	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the access token lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
	// SessionID identifies the session the tokens belong to.
	SessionID string `json:"session_id"`
}

// RotateRefreshToken exchanges a refresh token for a new access and refresh token pair.
//
// A token presented after its session was already rotated out is treated as
// reuse — the sign of a stolen token — and triggers the tenant's TokenReusePolicy
// before the request is refused. The one exception is the grace window: for
// cfg.SessionGracePeriod after a rotation the superseded token still answers with
// a fresh access token, so requests already in flight when the rotation landed do
// not fail. That reply omits the refresh token, since the new secret was already
// returned to whichever request performed the rotation.
//
// A session ended deliberately rather than rotated is not reuse, and is reported
// as ErrSessionRevoked without invoking the reuse policy.
//
// Returns ErrSessionNotFound if the token matches no session, ErrSessionExpired
// if the session's own lifetime has elapsed, ErrSessionRevoked when the session
// was revoked outright, and ErrSessionCompromised when reuse was detected and
// sessions were revoked.
func (s *Service) RotateRefreshToken(ctx context.Context, tenantID, environment, rawRefreshToken, clientIP, userAgent string) (*SessionTokenPairResponse, error) {
	if rawRefreshToken == "" {
		return nil, errors.New("refresh_token is required")
	}

	hash := HashRefreshToken(rawRefreshToken)
	sess, err := s.repo.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	// revokeOnCompromise applies the tenant's TokenReusePolicy. "session_revoke"
	// kills only the offending session; every other value, including an
	// unreadable policy, falls back to revoking all of the user's sessions.
	//
	// The policy is read for the environment the refresh is happening in, since a
	// tenant configures the two independently and a sandbox reuse policy has no
	// business deciding how a live compromise is handled.
	revokeOnCompromise := func(tID, uID, sID string) {
		if s.repo.Factory() != nil && tID != "" {
			policyRepo := policy.NewRepository(s.repo.Factory())
			secPol, err := policyRepo.GetSecurityPolicy(ctx, tID, environment)
			if err == nil && secPol.TokenReusePolicy == "session_revoke" {
				// Announced only once the session is actually gone. The event asserts
				// that the credential no longer answers, and a subscriber acting on a
				// compromise it was told was contained would stop looking.
				if revokeErr := s.repo.RevokeSession(ctx, sID); revokeErr == nil {
					s.emit(tID, environment, "session.revoked", map[string]interface{}{
						"user_id":    uID,
						"session_id": sID,
						"scope":      "session",
						"reason":     "refresh_token_reuse",
					})
				}
				return
			}
		}
		revoked, revokeErr := s.repo.RevokeAllUserSessions(ctx, uID, "")
		if revokeErr == nil {
			s.emit(tID, environment, "session.revoked", map[string]interface{}{
				"user_id": uID,
				"scope":   "all",
				"reason":  "refresh_token_reuse",
				"count":   revoked,
			})
		}
	}

	// A revoked session carrying a successor is reuse: the secret presented here
	// was already exchanged for another one, which is what a stolen token looks
	// like. With no successor the session was ended outright — an administrator
	// signing the account out, a restriction, or the sweeper — and its holder is
	// the legitimate owner of a token that has simply stopped working. Reporting
	// that as theft would misname it, and under the default reuse policy would also
	// revoke every session the owner has established since.
	if sess.Status == session.StatusRevoked {
		if sess.SupersededBySessionID != nil {
			revokeOnCompromise(tenantID, sess.UserID, sess.ID)
			return nil, ErrSessionCompromised
		}
		return nil, ErrSessionRevoked
	}

	if sess.Status == session.StatusRotatedGrace {
		if sess.GraceExpiresAt != nil && time.Now().After(*sess.GraceExpiresAt) {
			revokeOnCompromise(tenantID, sess.UserID, sess.ID)
			return nil, ErrSessionCompromised
		}

		// Inside the grace window: mint an access token against the session that
		// superseded this one and withhold the refresh token.
		if sess.SupersededBySessionID != nil {
			supersededSess, err := s.repo.GetSessionByID(ctx, *sess.SupersededBySessionID)
			if err == nil && supersededSess.Status == session.StatusActive {
				userObj, err := s.getUserByID(ctx, supersededSess.UserID)
				if err != nil {
					return nil, fmt.Errorf("failed to load session user: %w", err)
				}
				if err := accountstatus.Allowed(userObj); err != nil {
					return nil, err
				}

				accessToken, err := jwtpkg.IssueAccessTokenWithSession(userObj.ID, tenantID, environment, userObj.Email, userObj.Name, s.resolveRoleClaim(ctx, userObj.ID), supersededSess.ID, s.cfg.EncryptionKey, s.accessTokenTTL(ctx, tenantID, environment))
				if err != nil {
					return nil, fmt.Errorf("failed to issue access token: %w", err)
				}

				return &SessionTokenPairResponse{
					AccessToken:  accessToken,
					RefreshToken: "",
					TokenType:    "Bearer",
					ExpiresIn:    s.accessTokenExpiresIn(ctx, tenantID, environment),
					SessionID:    supersededSess.ID,
				}, nil
			}
		}
	}

	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	userObj, err := s.getUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}

	// Checked before the rotation write, so a refused refresh leaves the session
	// exactly as it was rather than consuming the caller's token in the process of
	// turning them away.
	if err := accountstatus.Allowed(userObj); err != nil {
		return nil, err
	}

	newSess, newRawToken, err := s.repo.RotateSession(ctx, tenantID, environment, sess.ID, "", s.cfg.SessionGracePeriod, s.cfg.RefreshTokenTTLFor(environment))
	if err != nil {
		return nil, fmt.Errorf("failed to rotate session: %w", err)
	}

	accessToken, err := jwtpkg.IssueAccessTokenWithSession(userObj.ID, tenantID, environment, userObj.Email, userObj.Name, s.resolveRoleClaim(ctx, userObj.ID), newSess.ID, s.cfg.EncryptionKey, s.accessTokenTTL(ctx, tenantID, environment))
	if err != nil {
		return nil, fmt.Errorf("failed to issue access token: %w", err)
	}

	return &SessionTokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: newRawToken,
		TokenType:    "Bearer",
		ExpiresIn:    s.accessTokenExpiresIn(ctx, tenantID, environment),
		SessionID:    newSess.ID,
	}, nil
}

// ListUserSessions returns the user's unexpired, unrevoked sessions, flagging the
// one matching currentSessionID. Returns an error if userID is empty or the query
// fails.
func (s *Service) ListUserSessions(ctx context.Context, userID, currentSessionID string) ([]SessionResponse, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	sessions, err := s.repo.GetUserActiveSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active sessions: %w", err)
	}

	resp := make([]SessionResponse, 0, len(sessions))
	for _, sess := range sessions {
		lastActive := ""
		if sess.LastActiveAt != nil {
			lastActive = sess.LastActiveAt.Format(time.RFC3339)
		}

		resp = append(resp, SessionResponse{
			ID:           sess.ID,
			Device:       ParseUserAgent(sess.UserAgent),
			IPAddress:    sess.IPAddress,
			Location:     sess.Location,
			LastActiveAt: lastActive,
			CreatedAt:    sess.CreatedAt.Format(time.RFC3339),
			IsCurrent:    sess.ID == currentSessionID,
		})
	}

	return resp, nil
}

// RevokeSession revokes targetSessionID.
//
// Ownership is verified before the revocation: a caller may only revoke a session
// that belongs to them. Returns ErrSessionNotFound if no such session exists and
// ErrSessionNotOwned if it belongs to a different user.
func (s *Service) RevokeSession(ctx context.Context, userID, targetSessionID string) error {
	if userID == "" || targetSessionID == "" {
		return errors.New("user_id and session_id are required")
	}

	sess, err := s.repo.GetSessionByID(ctx, targetSessionID)
	if err != nil {
		return ErrSessionNotFound
	}

	if sess.UserID != userID {
		return ErrSessionNotOwned
	}

	if err := s.repo.RevokeSession(ctx, targetSessionID); err != nil {
		return err
	}

	s.emitSessionRevoked(ctx, userID, map[string]interface{}{
		"session_id": targetSessionID,
		"scope":      "session",
		"reason":     "user_request",
	})

	return nil
}

// RevokeOtherSessions revokes every session belonging to userID except
// currentSessionID and returns the number revoked.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) (int, error) {
	if userID == "" {
		return 0, errors.New("user_id is required")
	}

	revoked, err := s.repo.RevokeAllUserSessions(ctx, userID, currentSessionID)
	if err != nil {
		return revoked, err
	}

	s.emitSessionRevoked(ctx, userID, map[string]interface{}{
		"scope":  "others",
		"reason": "user_request",
		"count":  revoked,
	})

	return revoked, nil
}

// RevokeAllSessions revokes every session belonging to userID, including the
// caller's own, and returns the number revoked.
func (s *Service) RevokeAllSessions(ctx context.Context, userID string) (int, error) {
	if userID == "" {
		return 0, errors.New("user_id is required")
	}

	revoked, err := s.repo.RevokeAllUserSessions(ctx, userID, "")
	if err != nil {
		return revoked, err
	}

	s.emitSessionRevoked(ctx, userID, map[string]interface{}{
		"scope":  "all",
		"reason": "user_request",
		"count":  revoked,
	})

	return revoked, nil
}

// ResolveSessionByRefreshToken returns the session ID and owning user ID for a
// raw refresh token, without rotating or revoking anything.
//
// Sign-out needs this because the access token is deliberately short-lived: a
// browser idle past that lifetime still holds a valid refresh cookie, and
// resolving the session from the access token alone would clear the cookie while
// leaving the session live for the rest of the refresh lifetime — the user would
// appear signed out while their session kept working.
//
// The lookup is tenant-scoped by the privacy interceptor through the session's
// user edge, so a token minted for another tenant does not resolve here.
// Returns ErrSessionNotFound when no session matches the token.
func (s *Service) ResolveSessionByRefreshToken(ctx context.Context, rawRefreshToken string) (sessionID string, userID string, err error) {
	if rawRefreshToken == "" {
		return "", "", ErrSessionNotFound
	}

	sess, err := s.repo.GetSessionByTokenHash(ctx, HashRefreshToken(rawRefreshToken))
	if err != nil {
		return "", "", ErrSessionNotFound
	}
	return sess.ID, sess.UserID, nil
}

// accessTokenExpiresIn returns the access token lifetime for tenantID in
// environment in whole seconds, the unit the OAuth token response uses.
//
// It resolves the lifetime through accessTokenTTL, the same helper the signer is
// handed, so the number advertised here and the `exp` actually signed cannot
// disagree — including where the tenant has chosen one and where the test ceiling
// shortens it.
func (s *Service) accessTokenExpiresIn(ctx context.Context, tenantID, environment string) int {
	return int(s.accessTokenTTL(ctx, tenantID, environment).Seconds())
}

// getUserByID loads the user record backing a session, for the claims placed in
// a freshly issued access token.
func (s *Service) getUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}

// resolveRoleClaim derives the JWT role claim from the user's recorded roles, so
// that a rotated session keeps console privilege rather than silently downgrading
// a tenant admin to a regular end user.
func (s *Service) resolveRoleClaim(ctx context.Context, userID string) string {
	return rbac.ResolveConsoleRoleClaim(ctx, s.repo.factory.GetClient(ctx, "", ""), userID)
}
