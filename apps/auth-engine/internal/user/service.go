/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/service.go
 * Tier: Business Logic Layer / User Profile & Settings Service
 *
 * Description: Business logic for user self-service: profile updates, password changes,
 *              primary email change and recovery email registration (both confirmed by
 *              single-use emailed tokens), linked social account management, and account
 *              erasure with its dependent records.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/trusteddevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

// Fallback lifetimes and origin, applied only when the service is constructed
// without a *config.Config. They reproduce the defaults config.Load gives
// EmailVerificationTTL, RecoveryTokenTTL and APP_BASE_URL.
const (
	// fallbackEmailChangeTokenTTL bounds how long a primary-email change link
	// works. Kept short because following it moves the address used to sign in.
	fallbackEmailChangeTokenTTL = 1 * time.Hour
	// fallbackRecoveryEmailTokenTTL bounds how long a recovery-email
	// confirmation link works. Longer than the primary-email window, since
	// confirming a secondary address grants no immediate access.
	fallbackRecoveryEmailTokenTTL = 24 * time.Hour
	// fallbackVerificationBaseURL is the origin prefixed to emailed links.
	fallbackVerificationBaseURL = "http://localhost:8080"
)

// Keys under which pending-verification state is held in a user's metadata bag.
// Writer and reader must agree exactly, so each key is named once here.
const (
	// metaPendingNewEmail holds the address awaiting confirmation.
	metaPendingNewEmail = "pending_new_email"
	// metaPendingEmailTokenHash holds the SHA-256 digest of the emailed token.
	metaPendingEmailTokenHash = "pending_email_token_hash"
	// metaPendingEmailExpiresAt holds that token's expiry, in Unix seconds.
	metaPendingEmailExpiresAt = "pending_email_expires_at"

	// metaRecoveryEmail holds the secondary recovery address.
	metaRecoveryEmail = "recovery_email"
	// metaRecoveryEmailVerified reports whether that address was confirmed.
	metaRecoveryEmailVerified = "recovery_email_verified"
	// metaRecoveryEmailTokenHash holds the SHA-256 digest of the emailed token.
	metaRecoveryEmailTokenHash = "recovery_email_token_hash"
	// metaRecoveryEmailExpiresAt holds that token's expiry, in Unix seconds.
	metaRecoveryEmailExpiresAt = "recovery_email_expires_at"
)

// Service implements the user self-service operations.
type Service struct {
	// authRepo provides the shared user store and ent client factory.
	authRepo *auth.Repository
	// emailProvider delivers verification mail. Nil disables delivery, which
	// leaves the token retrievable only from the service's return value.
	emailProvider email.EmailProvider
	// policyRepo supplies the tenant password policy. Nil skips policy checks.
	policyRepo *policy.Repository
	// webhookDispatcher publishes account lifecycle events. Nil disables them.
	webhookDispatcher *webhook.Dispatcher
	// cfg supplies token lifetimes and the public origin used to build emailed
	// links. Nil falls back to the constants above.
	cfg *config.Config
}

// NewService constructs a user Service. emailProvider, policyRepo and
// webhookDispatcher are each optional and may be nil.
//
// cfg is variadic only so existing callers keep compiling; pass it in
// application code. Without it, emailed verification links point at the local
// development origin rather than the deployment's own address.
func NewService(authRepo *auth.Repository, emailProvider email.EmailProvider, policyRepo *policy.Repository, webhookDispatcher *webhook.Dispatcher, cfg ...*config.Config) *Service {
	s := &Service{
		authRepo:          authRepo,
		emailProvider:     emailProvider,
		policyRepo:        policyRepo,
		webhookDispatcher: webhookDispatcher,
	}
	if len(cfg) > 0 {
		s.cfg = cfg[0]
	}
	return s
}

// emailChangeTokenTTL returns how long a primary-email change link stays valid.
func (s *Service) emailChangeTokenTTL() time.Duration {
	if s.cfg != nil && s.cfg.EmailVerificationTTL > 0 {
		return s.cfg.EmailVerificationTTL
	}
	return fallbackEmailChangeTokenTTL
}

// recoveryEmailTokenTTL returns how long a recovery-email confirmation link
// stays valid.
func (s *Service) recoveryEmailTokenTTL() time.Duration {
	if s.cfg != nil && s.cfg.RecoveryTokenTTL > 0 {
		return s.cfg.RecoveryTokenTTL
	}
	return fallbackRecoveryEmailTokenTTL
}

// verificationBaseURL returns the origin prefixed to emailed verification
// links, which must be the address a recipient's browser can actually reach.
func (s *Service) verificationBaseURL() string {
	if s.cfg != nil && s.cfg.AppBaseURL != "" {
		return s.cfg.AppBaseURL
	}
	return fallbackVerificationBaseURL
}

// newVerificationToken returns a random single-use token carrying the given
// prefix, together with the SHA-256 digest to store in its place.
//
// Only the digest is persisted, so reading the database yields no usable token.
func newVerificationToken(prefix string) (token, tokenHash string, err error) {
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed generating random token: %w", err)
	}
	token = prefix + hex.EncodeToString(tokenBytes)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// hashVerificationToken returns the stored digest form of a presented token.
func hashVerificationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// metadataUnixTime reads a Unix-seconds timestamp out of a metadata bag.
//
// Metadata makes a JSON round trip through the database, so a value written as
// int64 comes back as float64; both are accepted. ok is false when the key is
// absent or holds something non-numeric, which callers must treat as a failure
// rather than as "no expiry".
func metadataUnixTime(meta map[string]interface{}, key string) (time.Time, bool) {
	switch v := meta[key].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case int:
		return time.Unix(int64(v), 0), true
	default:
		return time.Time{}, false
	}
}

// GetProfile returns the profile of userID, or ErrUserNotFound if no such
// account exists.
func (s *Service) GetProfile(ctx context.Context, userID string) (*UserProfileResponse, error) {
	u, err := s.authRepo.GetUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, ErrUserNotFound
	}

	res := &UserProfileResponse{
		ID:            u.ID,
		TenantID:      u.TenantID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		PhoneNumber:   u.PhoneNumber,
		PhoneVerified: u.PhoneVerified,
		AvatarURL:     u.AvatarURL,
		Locale:        u.Locale,
		Metadata:      u.Metadata,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}

	if recEmail, ok := u.Metadata[metaRecoveryEmail].(string); ok {
		res.RecoveryEmail = recEmail
	}
	if recVer, ok := u.Metadata[metaRecoveryEmailVerified].(bool); ok {
		res.RecoveryEmailVerified = recVer
	}

	return res, nil
}

// UpdateProfile applies a partial update to the account's non-sensitive
// attributes and returns the resulting profile.
//
// Each supplied field is sanitised before it is stored, since name, avatar URL
// and locale are rendered back to browsers. Metadata is merged rather than
// replaced. Returns ErrUserNotFound for an unknown account, or a wrapped
// validation error naming the offending field.
func (s *Service) UpdateProfile(ctx context.Context, userID string, req UpdateProfileRequest) (*UserProfileResponse, error) {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return nil, ErrUserNotFound
	}

	updater := client.User.UpdateOneID(userID)

	if req.Name != nil {
		cleanName, err := validator.SanitizeString(*req.Name, 1, 100)
		if err != nil {
			return nil, fmt.Errorf("invalid name: %w", err)
		}
		updater.SetName(cleanName)
	}
	if req.AvatarURL != nil {
		cleanURL, err := validator.ValidateImageURL(*req.AvatarURL)
		if err != nil {
			return nil, fmt.Errorf("invalid avatar URL: %w", err)
		}
		updater.SetAvatarURL(cleanURL)
	}
	if req.Locale != nil {
		cleanLocale, err := validator.SanitizeString(*req.Locale, 2, 20)
		if err != nil {
			return nil, fmt.Errorf("invalid locale: %w", err)
		}
		updater.SetLocale(cleanLocale)
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	if req.Metadata != nil {
		for k, v := range req.Metadata {
			meta[k] = v
		}
		updater.SetMetadata(meta)
	}

	updatedUser, err := updater.Save(sysCtx)
	if err != nil {
		return nil, fmt.Errorf("failed updating user profile: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(u.TenantID, "user.updated", map[string]interface{}{
			"user_id": updatedUser.ID,
			"email":   updatedUser.Email,
			"name":    updatedUser.Name,
		})
	}

	return s.GetProfile(ctx, userID)
}

// ChangePassword replaces the account password after re-authenticating the caller.
//
// The current password must verify whenever the account has one; accounts with no
// password (social-only sign-in) can set one without that step. The replacement is
// checked against the tenant password policy before it is hashed. Returns
// ErrUserNotFound, ErrIncorrectPassword, or an error naming the unmet policy
// requirements.
func (s *Service) ChangePassword(ctx context.Context, tenantID, env, userID string, currentPassword, newPassword string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	if u.PasswordHash != "" {
		if !crypto.VerifyPasswordArgon2id(currentPassword, u.PasswordHash) {
			return ErrIncorrectPassword
		}
	}

	if s.policyRepo != nil {
		pol, err := s.policyRepo.GetPasswordPolicy(sysCtx, tenantID)
		if err == nil {
			missing := policy.ValidatePassword(pol, newPassword)
			if len(missing) > 0 {
				return fmt.Errorf("password does not meet policy requirements: missing %v", missing)
			}
		}
	}

	newHash, err := crypto.HashPasswordArgon2id(newPassword)
	if err != nil {
		return fmt.Errorf("failed hashing password: %w", err)
	}

	err = client.User.UpdateOneID(userID).
		SetPasswordHash(newHash).
		Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed saving updated password hash: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(tenantID, "password.changed", map[string]interface{}{
			"user_id": userID,
			"email":   u.Email,
		})
	}

	return nil
}

// RequestEmailChange records a pending change of the primary email address and
// mails a single-use confirmation link to the proposed address, returning the
// raw token.
//
// The link goes to the new address, not the current one, so possession of the
// address being claimed is what authorises the change. Nothing on the account
// changes until VerifyEmailChange consumes the token. Returns
// ErrEmailAlreadyInUse when the address is taken within the same tenant and
// environment, or ErrUserNotFound for an unknown account.
func (s *Service) RequestEmailChange(ctx context.Context, tenantID, env, userID, newEmail string) (string, error) {
	if err := validator.ValidateEmail(newEmail); err != nil {
		return "", err
	}
	newEmail = strings.TrimSpace(strings.ToLower(newEmail))

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	exists, err := client.User.Query().
		Where(user.TenantID(tenantID), user.EnvironmentEQ(user.Environment(env)), user.Email(newEmail)).
		Exist(sysCtx)
	if err != nil {
		return "", err
	}
	if exists {
		return "", ErrEmailAlreadyInUse
	}

	tokenStr, tokenHash, err := newVerificationToken("emc_")
	if err != nil {
		return "", err
	}

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return "", ErrUserNotFound
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	meta[metaPendingNewEmail] = newEmail
	meta[metaPendingEmailTokenHash] = tokenHash
	meta[metaPendingEmailExpiresAt] = time.Now().Add(s.emailChangeTokenTTL()).Unix()

	err = client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return "", fmt.Errorf("failed saving pending email token: %w", err)
	}

	if s.emailProvider != nil {
		subject := "Verify your new email address"
		body := fmt.Sprintf("Click the link to verify your new email: %s/v1/client/user/email/verify?token=%s", s.verificationBaseURL(), tokenStr)
		_ = s.emailProvider.Send(sysCtx, newEmail, subject, body, body)
	}

	return tokenStr, nil
}

// VerifyEmailChange consumes an email-change token and promotes the pending
// address to the account's verified primary email.
//
// Returns ErrInvalidVerificationToken when the token is unknown, carries no
// pending address, or has passed its recorded expiry. A record whose expiry is
// missing or unreadable is rejected on the same footing, so an unverifiable
// token is never treated as a valid one.
func (s *Service) VerifyEmailChange(ctx context.Context, tokenStr string) error {
	tokenHash := hashVerificationToken(tokenStr)

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	users, err := client.User.Query().All(sysCtx)
	if err != nil {
		return err
	}

	var targetUser *ent.User
	for _, u := range users {
		if metaHash, ok := u.Metadata[metaPendingEmailTokenHash].(string); ok && metaHash == tokenHash {
			targetUser = u
			break
		}
	}

	if targetUser == nil {
		return ErrInvalidVerificationToken
	}

	expiresAt, ok := metadataUnixTime(targetUser.Metadata, metaPendingEmailExpiresAt)
	if !ok || time.Now().After(expiresAt) {
		return ErrInvalidVerificationToken
	}

	newEmail, _ := targetUser.Metadata[metaPendingNewEmail].(string)
	if newEmail == "" {
		return ErrInvalidVerificationToken
	}

	// Clearing the pending keys in the same write that sets the address is what
	// makes the token single-use.
	meta := targetUser.Metadata
	delete(meta, metaPendingNewEmail)
	delete(meta, metaPendingEmailTokenHash)
	delete(meta, metaPendingEmailExpiresAt)

	err = client.User.UpdateOneID(targetUser.ID).
		SetEmail(newEmail).
		SetEmailVerified(true).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed updating primary email: %w", err)
	}

	return nil
}

// SetRecoveryEmail records a secondary recovery address and mails a single-use
// confirmation link to it, returning the raw token.
//
// The address is stored immediately but marked unverified, so it cannot be used
// for recovery until VerifyRecoveryEmail confirms it. Returns ErrUserNotFound for
// an unknown account.
func (s *Service) SetRecoveryEmail(ctx context.Context, tenantID, env, userID, recoveryEmail string) (string, error) {
	if err := validator.ValidateEmail(recoveryEmail); err != nil {
		return "", err
	}
	recoveryEmail = strings.TrimSpace(strings.ToLower(recoveryEmail))

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return "", ErrUserNotFound
	}

	tokenStr, tokenHash, err := newVerificationToken("rec_")
	if err != nil {
		return "", err
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	meta[metaRecoveryEmail] = recoveryEmail
	meta[metaRecoveryEmailVerified] = false
	meta[metaRecoveryEmailTokenHash] = tokenHash
	meta[metaRecoveryEmailExpiresAt] = time.Now().Add(s.recoveryEmailTokenTTL()).Unix()

	err = client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return "", fmt.Errorf("failed setting recovery email: %w", err)
	}

	if s.emailProvider != nil {
		subject := "Verify your secondary recovery email"
		body := fmt.Sprintf("Click the link to verify your recovery email: %s/v1/client/user/recovery-email/verify?token=%s", s.verificationBaseURL(), tokenStr)
		_ = s.emailProvider.Send(sysCtx, recoveryEmail, subject, body, body)
	}

	return tokenStr, nil
}

// VerifyRecoveryEmail consumes a recovery-email token and marks the secondary
// address verified.
//
// Returns ErrInvalidVerificationToken when the token is unknown or has passed its
// recorded expiry. A record whose expiry is missing or unreadable is rejected on
// the same footing, so an unverifiable token is never treated as a valid one.
func (s *Service) VerifyRecoveryEmail(ctx context.Context, tokenStr string) error {
	tokenHash := hashVerificationToken(tokenStr)

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	users, err := client.User.Query().All(sysCtx)
	if err != nil {
		return err
	}

	var targetUser *ent.User
	for _, u := range users {
		if metaHash, ok := u.Metadata[metaRecoveryEmailTokenHash].(string); ok && metaHash == tokenHash {
			targetUser = u
			break
		}
	}

	if targetUser == nil {
		return ErrInvalidVerificationToken
	}

	expiresAt, ok := metadataUnixTime(targetUser.Metadata, metaRecoveryEmailExpiresAt)
	if !ok || time.Now().After(expiresAt) {
		return ErrInvalidVerificationToken
	}

	// Clearing the token keys in the same write that flips the verified flag is
	// what makes the token single-use.
	meta := targetUser.Metadata
	meta[metaRecoveryEmailVerified] = true
	delete(meta, metaRecoveryEmailTokenHash)
	delete(meta, metaRecoveryEmailExpiresAt)

	err = client.User.UpdateOneID(targetUser.ID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed verifying recovery email: %w", err)
	}

	return nil
}

// DeleteRecoveryEmail removes the secondary recovery address and any pending
// confirmation for it. Returns ErrUserNotFound for an unknown account.
func (s *Service) DeleteRecoveryEmail(ctx context.Context, userID string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	meta := u.Metadata
	delete(meta, metaRecoveryEmail)
	delete(meta, metaRecoveryEmailVerified)
	delete(meta, metaRecoveryEmailTokenHash)
	delete(meta, metaRecoveryEmailExpiresAt)

	return client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
}

// ListSocialAccounts returns the OAuth identities linked to the account, or an
// empty slice when none are.
func (s *Service) ListSocialAccounts(ctx context.Context, userID string) ([]LinkedSocialAccount, error) {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	identities, err := client.Identity.Query().
		Where(identity.UserID(userID)).
		All(sysCtx)
	if err != nil {
		return nil, err
	}

	accounts := make([]LinkedSocialAccount, 0, len(identities))
	for _, id := range identities {
		accounts = append(accounts, LinkedSocialAccount{
			Provider:       id.Provider,
			ProviderUserID: id.ProviderUserID,
			Email:          id.Email,
			ConnectedAt:    id.CreatedAt,
		})
	}

	return accounts, nil
}

// UnlinkSocialAccount disconnects the named provider from the account.
//
// Returns ErrUserNotFound, ErrSocialNotConnected when the provider is not linked,
// or ErrCannotUnlinkLastAuth when removing it would leave the account with no way
// to sign in — no password and no other identity.
func (s *Service) UnlinkSocialAccount(ctx context.Context, userID string, providerName string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	identities, err := client.Identity.Query().
		Where(identity.UserID(userID)).
		All(sysCtx)
	if err != nil {
		return err
	}

	var targetIdentity *ent.Identity
	for _, id := range identities {
		if strings.EqualFold(id.Provider, providerName) {
			targetIdentity = id
			break
		}
	}

	if targetIdentity == nil {
		return ErrSocialNotConnected
	}

	if u.PasswordHash == "" && len(identities) <= 1 {
		return ErrCannotUnlinkLastAuth
	}

	return client.Identity.DeleteOneID(targetIdentity.ID).Exec(sysCtx)
}

// DeleteAccount permanently erases the account and its dependent records, after
// re-authenticating the caller.
//
// The password must verify whenever the account has one. Child records are purged
// before the user row so foreign keys never block the deletion, and because
// leaving sessions or credentials behind would outlive the account they belong
// to. Returns ErrUserNotFound or ErrIncorrectPassword.
func (s *Service) DeleteAccount(ctx context.Context, tenantID, env, userID string, confirmPassword string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	if u.PasswordHash != "" {
		if !crypto.VerifyPasswordArgon2id(confirmPassword, u.PasswordHash) {
			return ErrIncorrectPassword
		}
	}

	_, _ = client.Session.Delete().Where(session.UserID(userID)).Exec(sysCtx)
	_, _ = client.OrgMember.Delete().Where(orgmember.UserID(userID)).Exec(sysCtx)
	_, _ = client.TwoFactorMethod.Delete().Where(twofactormethod.UserID(userID)).Exec(sysCtx)
	_, _ = client.TrustedDevice.Delete().Where(trusteddevice.UserID(userID)).Exec(sysCtx)
	_, _ = client.Identity.Delete().Where(identity.UserID(userID)).Exec(sysCtx)
	_, _ = client.RecoveryContact.Delete().Where(recoverycontact.UserID(userID)).Exec(sysCtx)

	err = client.User.DeleteOneID(userID).Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed deleting user account: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(tenantID, "user.deleted", map[string]interface{}{
			"user_id": userID,
			"email":   u.Email,
		})
	}

	return nil
}
