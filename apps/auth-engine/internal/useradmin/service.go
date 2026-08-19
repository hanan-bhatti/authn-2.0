/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/useradmin/service.go
 * Tier: Domain Layer / Account Lifecycle Administration
 *
 * The administrative side of an account's lifecycle: ban, suspend, reinstate,
 * retire, restore, and forced sign-out.
 *
 * Restricting an account takes three writes, not one. The status column stops
 * the next sign-in; revoking the sessions stops a refresh from minting a
 * replacement token; and the per-user issued-at cutoff refuses the access tokens
 * already in circulation. Access tokens are self-contained and verified without
 * touching the database, so a ban that only writes the column begins whenever
 * the last outstanding token happens to expire — up to a full access-token
 * lifetime after the operator was told the account was banned. Every restricting
 * transition here performs all three, and every lifting transition clears the
 * cutoff so access resumes immediately rather than waiting out its TTL.
 *
 * Each transition loads the user before writing. The privacy layer already
 * confines the write to the caller's tenant, so this is not what provides
 * isolation; it is what lets a transition refuse on the account's current state
 * — a distinction the write alone cannot make, since an update that changes
 * nothing still succeeds.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package useradmin

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
)

// cutoffSkewMargin extends an issued-at cutoff past the access-token lifetime.
//
// The cutoff compares a token's iat against a wall-clock instant recorded on a
// different machine. A token minted by an instance whose clock runs behind the
// one placing the restriction would carry an iat slightly in the past, and a
// cutoff expiring at exactly the token lifetime could lapse while such a token
// was still valid.
const cutoffSkewMargin = 2 * time.Minute

// Refusals a transition can raise. Handlers match these with errors.Is to pick
// a status code, so their identity matters rather than their text.
var (
	// ErrUserNotFound reports no such user in the caller's tenant. A user in
	// another tenant produces this too, by way of the privacy layer.
	ErrUserNotFound = errors.New("user not found")
	// ErrAlreadyInState reports a transition whose target status the account
	// already holds.
	ErrAlreadyInState = errors.New("account is already in the requested state")
	// ErrNotInState reports a lifting transition against an account that does not
	// hold the restriction being lifted — unbanning a suspended account, say.
	ErrNotInState = errors.New("account does not hold the restriction being lifted")
	// ErrRecoveryHoldActive reports a restriction attempted during the security
	// freeze that follows account recovery.
	ErrRecoveryHoldActive = errors.New("account is under a recovery hold")
	// ErrUserDeleted reports a status change attempted on a retired account.
	ErrUserDeleted = errors.New("account is deleted")
	// ErrNotDeleted reports a restore attempted on an account that is not retired.
	ErrNotDeleted = errors.New("account is not deleted")
	// ErrSelfAction reports an administrator restricting or retiring their own
	// account. Allowing it would let one mistaken request remove the access needed
	// to undo itself.
	ErrSelfAction = errors.New("an administrator cannot restrict their own account")
	// ErrUsernameTaken reports a username already held by another account in the
	// same tenant and environment.
	ErrUsernameTaken = errors.New("username is already taken")
)

// Actor identifies who performed an administrative action, and is recorded on
// every audit row this package writes.
//
// Admin authentication has two forms and they identify their caller differently:
// a secret key names the key, and a console session names the administrator
// holding it. Both are carried so that neither kind of caller is anonymous in
// the audit trail.
type Actor struct {
	// ConsoleUserID and ConsoleUserEmail identify a console administrator.
	ConsoleUserID    string
	ConsoleUserEmail string
	// APIKeyID names the secret key, when one was used.
	APIKeyID string
	// AuthMethod is "secret_key" or "console_jwt".
	AuthMethod string
	// IPAddress, UserAgent and Origin are the request's network context.
	IPAddress string
	UserAgent string
	Origin    string
}

// Service applies the administrative account lifecycle rules.
type Service struct {
	// repo reads and writes the user directory and the audit trail.
	repo *Repository
	// sessions revokes refresh sessions, which is what stops a restricted
	// account from minting a replacement access token.
	sessions *session.Repository
	// blocklist holds the per-user issued-at cutoff. A nil blocklist — Redis
	// unconfigured — makes the cutoff a no-op, which degrades a restriction to
	// taking effect within one access-token lifetime rather than immediately.
	blocklist *tokenblocklist.Blocklist
	// accessTokenTTL sizes how long a cutoff must be retained. It is the
	// deployment-wide lifetime rather than one resolved per environment, because the
	// cutoff has to outlive the longest-lived token it could be asked about, and the
	// per-environment ceilings only ever shorten that.
	accessTokenTTL time.Duration
}

// NewService returns a service bound to its collaborators.
//
// sessions and blocklist are required parameters rather than options because a
// restriction that skips either one is not a restriction. A nil blocklist is
// still accepted — that is the documented no-op for a deployment without Redis —
// but it has to be passed deliberately.
func NewService(repo *Repository, sessions *session.Repository, blocklist *tokenblocklist.Blocklist, cfg *config.Config) *Service {
	ttl := time.Duration(0)
	if cfg != nil {
		ttl = cfg.AccessTokenTTL
	}
	return &Service{repo: repo, sessions: sessions, blocklist: blocklist, accessTokenTTL: ttl}
}

// List returns one page of the tenant's user directory and the total matching
// the filter.
func (s *Service) List(ctx context.Context, f ListFilter) ([]*ent.User, int, error) {
	return s.repo.List(ctx, f)
}

// Get returns one user, or ErrUserNotFound.
func (s *Service) Get(ctx context.Context, userID string) (*ent.User, error) {
	u, err := s.repo.Get(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
}

// ActiveSessionCount reports how many sessions the user could still refresh,
// which is what tells an administrator whether a ban has anything to cut off.
func (s *Service) ActiveSessionCount(ctx context.Context, userID string) (int, error) {
	if s.sessions == nil {
		return 0, nil
	}
	rows, err := s.sessions.GetUserActiveSessions(ctx, userID)
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// Detail is one account plus the context an operator needs before acting on it:
// how much live access a restriction would cut off, and what else the holder
// could sign in with.
type Detail struct {
	User            *ent.User
	ActiveSessions  int
	SocialProviders []string
	TwoFactorTypes  []string
}

// Detail returns one account and its sign-in surface.
//
// A failure in any of the supporting lookups is returned rather than reported as
// an empty list. "No second factor enrolled" and "the second-factor query
// failed" lead an operator to opposite decisions, and a list cannot express the
// difference.
func (s *Service) Detail(ctx context.Context, userID string) (*Detail, error) {
	u, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	sessions, err := s.ActiveSessionCount(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("counting active sessions: %w", err)
	}

	providers, err := s.repo.LinkedProviders(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("reading linked providers: %w", err)
	}

	factors, err := s.repo.EnabledTwoFactorTypes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("reading two-factor methods: %w", err)
	}

	return &Detail{
		User:            u,
		ActiveSessions:  sessions,
		SocialProviders: providers,
		TwoFactorTypes:  factors,
	}, nil
}

// Ban permanently bars an account.
//
// Lifting it is an administrative act; the account holder cannot retry past it.
func (s *Service) Ban(ctx context.Context, tenantID, userID, reason string, actor Actor) (*ent.User, error) {
	return s.restrict(ctx, tenantID, userID, user.StatusBanned, "admin.user.banned", reason, actor)
}

// Suspend places a reversible hold on an account.
func (s *Service) Suspend(ctx context.Context, tenantID, userID, reason string, actor Actor) (*ent.User, error) {
	return s.restrict(ctx, tenantID, userID, user.StatusSuspended, "admin.user.suspended", reason, actor)
}

// Unban returns a banned account to active.
//
// It refuses an account that is not banned, which is what keeps this from
// lifting a recovery hold: the freeze after an account recovery exists to hold
// an attacker out of an account they may have just taken over, and an ordinary
// administrative action must not be able to end it early.
func (s *Service) Unban(ctx context.Context, tenantID, userID, reason string, actor Actor) (*ent.User, error) {
	return s.lift(ctx, tenantID, userID, user.StatusBanned, "admin.user.unbanned", reason, actor)
}

// Unsuspend returns a suspended account to active, refusing any other status for
// the same reason Unban does.
func (s *Service) Unsuspend(ctx context.Context, tenantID, userID, reason string, actor Actor) (*ent.User, error) {
	return s.lift(ctx, tenantID, userID, user.StatusSuspended, "admin.user.unsuspended", reason, actor)
}

// restrict applies a restricting status and cuts off the account's live access.
//
// A recovery hold blocks this. The hold already refuses every authentication, so
// nothing is exposed by declining to overwrite it, and overwriting it would open
// a way around it: banning a frozen account and then unbanning it would leave
// the account active with the freeze gone. Retiring the account remains
// available for a case that genuinely cannot wait, because deletion is stored in
// its own column and a later restore returns the account to the hold.
//
// A console administrator cannot restrict the account they are signed in as.
// A secret key names no user, so the guard applies only to console callers —
// which is the only case where the actor and the target can be the same account.
func (s *Service) restrict(ctx context.Context, tenantID, userID string, status user.Status, event, reason string, actor Actor) (*ent.User, error) {
	if actor.ConsoleUserID != "" && actor.ConsoleUserID == userID {
		return nil, ErrSelfAction
	}

	u, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.DeletedAt != nil {
		return nil, ErrUserDeleted
	}
	if u.Status == status {
		return nil, ErrAlreadyInState
	}
	if u.Status == user.StatusRecoveryHold {
		return nil, ErrRecoveryHoldActive
	}

	if err := s.repo.SetStatus(ctx, userID, status); err != nil {
		return nil, fmt.Errorf("applying status %s: %w", status, err)
	}

	revoked := s.cutOffLiveAccess(ctx, userID)

	s.audit(ctx, tenantID, userID, event, reason, actor, map[string]interface{}{
		"previous_status":   string(u.Status),
		"new_status":        string(status),
		"sessions_revoked":  revoked,
		"access_tokens_cut": s.blocklist.Enabled(),
	})

	return s.reload(ctx, userID)
}

// lift removes a restriction, requiring the account to currently hold it.
func (s *Service) lift(ctx context.Context, tenantID, userID string, required user.Status, event, reason string, actor Actor) (*ent.User, error) {
	u, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.DeletedAt != nil {
		return nil, ErrUserDeleted
	}
	if u.Status != required {
		return nil, ErrNotInState
	}

	if err := s.repo.SetStatus(ctx, userID, user.StatusActive); err != nil {
		return nil, fmt.Errorf("clearing status %s: %w", required, err)
	}

	// The cutoff is dropped so the account can sign in at once. Its sessions stay
	// revoked: they were cut off while the restriction was in force and there is
	// no way to tell which of them the rightful owner still holds.
	s.blocklist.ClearUserTokenCutoff(ctx, userID)

	s.audit(ctx, tenantID, userID, event, reason, actor, map[string]interface{}{
		"previous_status": string(u.Status),
		"new_status":      string(user.StatusActive),
	})

	return s.reload(ctx, userID)
}

// SoftDelete retires an account, keeping the row so its email stays reserved.
//
// Sign-in is refused from that point regardless of status, and live access is
// cut off the same way a restriction cuts it off. A console administrator cannot
// retire the account they are signed in as.
func (s *Service) SoftDelete(ctx context.Context, tenantID, userID, reason string, actor Actor) error {
	if actor.ConsoleUserID != "" && actor.ConsoleUserID == userID {
		return ErrSelfAction
	}

	u, err := s.Get(ctx, userID)
	if err != nil {
		return err
	}
	if u.DeletedAt != nil {
		return ErrAlreadyInState
	}

	now := time.Now()
	if err := s.repo.SoftDelete(ctx, userID, now); err != nil {
		return fmt.Errorf("retiring account: %w", err)
	}

	revoked := s.cutOffLiveAccess(ctx, userID)

	s.audit(ctx, tenantID, userID, "admin.user.deleted", reason, actor, map[string]interface{}{
		"status_at_deletion": string(u.Status),
		"sessions_revoked":   revoked,
		"access_tokens_cut":  s.blocklist.Enabled(),
	})

	return nil
}

// Restore returns a retired account to service, leaving its status alone.
//
// An account banned before it was retired comes back banned. Deletion and status
// are separate columns, and collapsing them here would turn a restore into a
// way to clear a restriction.
func (s *Service) Restore(ctx context.Context, tenantID, userID, reason string, actor Actor) (*ent.User, error) {
	u, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.DeletedAt == nil {
		return nil, ErrNotDeleted
	}

	if err := s.repo.Restore(ctx, userID); err != nil {
		return nil, fmt.Errorf("restoring account: %w", err)
	}

	// Only an account that comes back unrestricted gets its cutoff dropped.
	// Leaving it in place for a still-banned account keeps the ban immediate.
	if u.Status == user.StatusActive {
		s.blocklist.ClearUserTokenCutoff(ctx, userID)
	}

	s.audit(ctx, tenantID, userID, "admin.user.restored", reason, actor, map[string]interface{}{
		"restored_to_status": string(u.Status),
		"deleted_at":         u.DeletedAt.UTC().Format(time.RFC3339),
	})

	return s.reload(ctx, userID)
}

// ForceLogout ends every session and refuses the account's outstanding access
// tokens without changing its status, which is the right response to a
// suspected token theft on an account that has done nothing wrong.
func (s *Service) ForceLogout(ctx context.Context, tenantID, userID, reason string, actor Actor) (int, error) {
	u, err := s.Get(ctx, userID)
	if err != nil {
		return 0, err
	}

	revoked := s.cutOffLiveAccess(ctx, userID)

	s.audit(ctx, tenantID, userID, "admin.user.sessions_revoked", reason, actor, map[string]interface{}{
		"status":            string(u.Status),
		"sessions_revoked":  revoked,
		"access_tokens_cut": s.blocklist.Enabled(),
	})

	return revoked, nil
}

// VerifyEmail marks an address verified on an administrator's authority, for the
// support case where the owner cannot receive mail at it.
func (s *Service) VerifyEmail(ctx context.Context, tenantID, userID string, actor Actor) (*ent.User, error) {
	u, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.EmailVerified {
		return nil, ErrAlreadyInState
	}

	if err := s.repo.MarkEmailVerified(ctx, userID); err != nil {
		return nil, fmt.Errorf("marking email verified: %w", err)
	}

	s.audit(ctx, tenantID, userID, "admin.user.email_verified", "", actor, map[string]interface{}{
		"email": u.Email,
	})

	return s.reload(ctx, userID)
}

// UpdateProfile applies an administrative profile change.
//
// A username is checked for collision inside the caller's tenant before it is
// written, since the column carries no unique constraint of its own.
//
// The changed field names are audited; their values are not. A profile carries
// personal data, and an audit trail an operator reads routinely is the wrong
// place to accumulate a second copy of it.
func (s *Service) UpdateProfile(ctx context.Context, tenantID, userID string, patch ProfilePatch, actor Actor) (*ent.User, error) {
	current, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	if patch.Username != nil && *patch.Username != "" {
		taken, err := s.repo.UsernameTaken(ctx, userID, *patch.Username)
		if err != nil {
			return nil, fmt.Errorf("checking username availability: %w", err)
		}
		if taken {
			return nil, ErrUsernameTaken
		}
	}

	updated, err := s.repo.UpdateProfile(ctx, current, patch)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	s.audit(ctx, tenantID, userID, "admin.user.updated", "", actor, map[string]interface{}{
		"fields_changed": changedFields(patch),
	})

	return updated, nil
}

// changedFields names the fields a patch touches, in a stable order so two
// identical patches produce identical audit metadata.
func changedFields(p ProfilePatch) []string {
	var fields []string
	if p.Name != nil {
		fields = append(fields, "name")
	}
	if p.Username != nil {
		fields = append(fields, "username")
	}
	if p.AvatarURL != nil {
		fields = append(fields, "avatar_url")
	}
	if p.PhoneNumber != nil {
		fields = append(fields, "phone_number")
	}
	if p.Locale != nil {
		fields = append(fields, "locale")
	}
	if p.Metadata != nil {
		fields = append(fields, "metadata")
	}
	return fields
}

// cutOffLiveAccess revokes the account's sessions and refuses every access token
// it has already been issued, returning how many sessions were revoked.
//
// Both halves are needed and neither substitutes for the other: revoking
// sessions stops the next refresh, and the cutoff stops the token the caller is
// holding right now. Failures are logged rather than returned — the status
// change that precedes this call has already committed, so reporting an error
// would describe a restriction that is partly in force as one that did not
// happen. The cutoff is written before the log line so a revocation failure does
// not skip it.
func (s *Service) cutOffLiveAccess(ctx context.Context, userID string) int {
	s.blocklist.BlockUserTokensIssuedBefore(ctx, userID, time.Now(), s.cutoffTTL())

	if s.sessions == nil {
		return 0
	}
	revoked, err := s.sessions.RevokeAllUserSessions(ctx, userID, "")
	if err != nil {
		log.Printf("[warn] useradmin: session revocation failed for user=%s: %v", userID, err)
		return 0
	}
	return revoked
}

// cutoffTTL is how long an issued-at cutoff must outlive the tokens it refuses.
//
// Past the access-token lifetime plus a clock-skew margin every token the cutoff
// covered has expired on its own, and the account's sessions were revoked
// alongside it, so no new token can have been minted in the meantime.
func (s *Service) cutoffTTL() time.Duration {
	ttl := s.accessTokenTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return ttl + cutoffSkewMargin
}

// reload re-reads a user after a write so the response reflects what was stored,
// including the updated_at the database stamped.
func (s *Service) reload(ctx context.Context, userID string) (*ent.User, error) {
	u, err := s.repo.Get(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("reading back user: %w", err)
	}
	return u, nil
}

// audit records one administrative action, folding the actor and the operator's
// stated reason into the metadata.
//
// The write is best-effort: the account change it describes is already durable,
// and failing the request over the record would leave the operator retrying an
// action that already took effect.
func (s *Service) audit(ctx context.Context, tenantID, userID, event, reason string, actor Actor, meta map[string]interface{}) {
	if meta == nil {
		meta = make(map[string]interface{})
	}
	if reason != "" {
		meta["reason"] = reason
	}
	if actor.AuthMethod != "" {
		meta["admin_auth_method"] = actor.AuthMethod
	}
	if actor.ConsoleUserID != "" {
		meta["actor_user_id"] = actor.ConsoleUserID
	}
	if actor.ConsoleUserEmail != "" {
		meta["actor_email"] = actor.ConsoleUserEmail
	}

	err := s.repo.WriteAudit(ctx, AuditEntry{
		TenantID:     tenantID,
		TargetUserID: userID,
		EventType:    event,
		APIKeyID:     actor.APIKeyID,
		IPAddress:    actor.IPAddress,
		UserAgent:    actor.UserAgent,
		Origin:       actor.Origin,
		Metadata:     meta,
	})
	if err != nil {
		log.Printf("[warn] useradmin: audit write failed for event=%s user=%s: %v", event, userID, err)
	}
}
