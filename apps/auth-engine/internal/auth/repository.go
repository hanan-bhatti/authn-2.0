/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/repository.go
 * Tier: Internal Feature Package / Auth Repository
 *
 * Description: Data access layer for authentication entities (Users, ApiKeys,
 *              Sessions, AuditLogs). Interacts directly with Ent ORM clients.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/predicate"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/securityblacklist"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// Repository handles database operations for authentication features.
type Repository struct {
	factory *clientfactory.ClientFactory
}

// NewRepository constructs a new Auth Repository instance.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// GetClientFactory returns the underlying ClientFactory instance.
func (r *Repository) GetClientFactory() *clientfactory.ClientFactory {
	return r.factory
}

// GetUserByID fetches a user record by ID.
func (r *Repository) GetUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}

// EnsureTenantExists checks if a tenant exists and creates a default record if missing.
func (r *Repository) EnsureTenantExists(ctx context.Context, tenantID string) error {
	client := r.factory.GetClient(ctx, tenantID, "test")
	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed checking tenant existence: %w", err)
	}
	if !exists {
		_, err := client.Tenant.Create().
			SetID(tenantID).
			SetName("Default Workspace").
			SetSlug(tenantID).
			Save(ctx)
		if err != nil && !ent.IsConstraintError(err) {
			return fmt.Errorf("failed auto-creating tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

// FindUserByEmail retrieves a user by email within a specific tenant and environment scope.
//
// Parameters:
//   - ctx: Request context.
//   - tenantID: Tenant ID scope.
//   - env: Environment mode ("test" or "live").
//   - email: Target registered email address.
//
// Returns:
//   - *ent.User: Found user record or nil.
//   - error: Non-nil if query fails.
func (r *Repository) FindUserByEmail(ctx context.Context, tenantID string, env string, email string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, tenantID, env)
	u, err := client.User.Query().
		Where(
			user.TenantID(tenantID),
			user.EnvironmentEQ(user.Environment(env)),
			user.Email(email),
		).
		Only(ctx)

	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying user by email: %w", err)
	}
	return u, nil
}

// CreateUser registers a new user in the database.
//
// Parameters:
//   - ctx: Request context.
//   - id: Unique User ID (`usr_...`).
//   - tenantID: Owning Tenant ID.
//   - env: Environment mode ("test" or "live").
//   - email: Registered email address.
//   - passwordHash: Argon2id password hash.
//   - name: Optional full name.
//
// Returns:
//   - *ent.User: Created user record.
//   - error: Non-nil if creation fails.
func (r *Repository) CreateUser(ctx context.Context, id string, tenantID string, env string, email string, passwordHash string, name string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, tenantID, env)
	u, err := client.User.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetEnvironment(user.Environment(env)).
		SetEmail(email).
		SetNillablePasswordHash(&passwordHash).
		SetNillableName(&name).
		Save(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed creating user record: %w", err)
	}
	return u, nil
}

// ClaimFirstAdminRole atomically claims the first-admin slot for a tenant.
//
// It issues a conditional UPDATE:
//
//	UPDATE tenants SET first_admin_claimed = true
//	WHERE id = ? AND first_admin_claimed = false
//
// The DB engine guarantees only one concurrent writer can flip false → true.
// The caller that gets n=1 (rows affected) is the first user and receives
// role="tenant_admin" in their JWT. All other concurrent callers get n=0
// and receive role="" (regular user). No transaction or advisory lock needed.
//
// This replaces the previous CountUsersByTenant-then-create pattern which
// had a TOCTOU race when two signups arrived concurrently on a new tenant.
func (r *Repository) ClaimFirstAdminRole(ctx context.Context, tenantID string) (bool, error) {
	client := r.factory.GetClient(ctx, tenantID, "test") // tenant-level, not env-scoped
	n, err := client.Tenant.Update().
		Where(
			tenant.ID(tenantID),
			tenant.FirstAdminClaimed(false),
		).
		SetFirstAdminClaimed(true).
		Save(ctx)
	if err != nil {
		return false, fmt.Errorf("failed claiming first admin role for tenant %s: %w", tenantID, err)
	}
	return n == 1, nil
}

// FindApiKeyByHash retrieves an API key by its hash.
//
// Parameters:
//   - ctx: Request context.
//   - keyHash: Peppered HMAC-SHA256 hash or raw publishable key string.
//
// Returns:
//   - *ent.ApiKey: Found API key record or nil.
//   - error: Non-nil if query fails.
func (r *Repository) FindApiKeyByHash(ctx context.Context, keyHash string) (*ent.ApiKey, error) {
	client := r.factory.GetClient(ctx, "", "")
	k, err := client.ApiKey.Query().
		Where(apikey.KeyHash(keyHash)).
		Only(ctx)

	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying api key by hash: %w", err)
	}
	return k, nil
}

// CreateSession initializes a new active login session.
//
// Parameters:
//   - ctx: Request context.
//   - id: Unique session ID (`ses_...`).
//   - userID: Owning User ID.
//   - tokenHash: SHA-256 hash of opaque refresh token.
//   - userAgent: HTTP User-Agent header string.
//   - ipAddress: Client IP address string.
//   - expiresAt: Session expiration timestamp.
//
// Returns:
//   - *ent.Session: Created session record.
//   - error: Non-nil if creation fails.
func (r *Repository) CreateSession(ctx context.Context, id string, userID string, tokenHash string, userAgent string, ipAddress string, expiresAt time.Time) (*ent.Session, error) {
	client := r.factory.GetClient(ctx, "", "")
	s, err := client.Session.Create().
		SetID(id).
		SetUserID(userID).
		SetRefreshTokenHash(tokenHash).
		SetStatus(session.StatusActive).
		SetNillableUserAgent(&userAgent).
		SetNillableIPAddress(&ipAddress).
		SetExpiresAt(expiresAt).
		Save(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed creating session: %w", err)
	}
	return s, nil
}

// RevokeAllSessionsForUser invalidates all active sessions for a user.
//
// Parameters:
//   - ctx: Request context.
//   - userID: Target User ID.
//
// Returns:
//   - error: Non-nil if update fails.
func (r *Repository) RevokeAllSessionsForUser(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.Session.Update().
		Where(
			session.UserID(userID),
			session.StatusNEQ(session.StatusRevoked),
		).
		SetStatus(session.StatusRevoked).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed revoking user sessions: %w", err)
	}
	return nil
}

// FindSessionByTokenHash retrieves a session by its SHA-256 refresh token hash.
func (r *Repository) FindSessionByTokenHash(ctx context.Context, tokenHash string) (*ent.Session, error) {
	client := r.factory.GetClient(ctx, "", "")
	s, err := client.Session.Query().
		Where(session.RefreshTokenHash(tokenHash)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed querying session by refresh token hash: %w", err)
	}
	return s, nil
}

// FindSessionByID retrieves a session by its unique ID.
func (r *Repository) FindSessionByID(ctx context.Context, sessionID string) (*ent.Session, error) {
	client := r.factory.GetClient(ctx, "", "")
	s, err := client.Session.Query().
		Where(session.ID(sessionID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed querying session by ID: %w", err)
	}
	return s, nil
}

// MarkSessionRotatedWithGrace transitions an active session to 'rotated_grace' status
// with a 10-second grace window expiration time.
func (r *Repository) MarkSessionRotatedWithGrace(ctx context.Context, oldSessionID string, newSessionID string, graceDuration time.Duration) error {
	client := r.factory.GetClient(ctx, "", "")
	graceExpiresAt := time.Now().Add(graceDuration)

	_, err := client.Session.UpdateOneID(oldSessionID).
		SetStatus(session.StatusRotatedGrace).
		SetSupersededBySessionID(newSessionID).
		SetGraceExpiresAt(graceExpiresAt).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed marking session as rotated with grace: %w", err)
	}
	return nil
}

// CreateAuditLog records an audit log entry for security and compliance tracking.
func (r *Repository) CreateAuditLog(ctx context.Context, id string, tenantID string, userID string, eventType string, ipAddress string, userAgent string, origin string) error {
	client := r.factory.GetClient(ctx, tenantID, "")
	_, err := client.AuditLog.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetNillableUserID(&userID).
		SetActorType(auditlog.ActorTypeUser).
		SetEventType(eventType).
		SetNillableIPAddress(&ipAddress).
		SetNillableUserAgent(&userAgent).
		SetNillableRequestOrigin(&origin).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed creating audit log: %w", err)
	}
	return nil
}

// UpdateUserLastSignIn updates the user's last_sign_in_at timestamp.
func (r *Repository) UpdateUserLastSignIn(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	now := time.Now()
	_, err := client.User.UpdateOneID(userID).
		SetLastSignInAt(now).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed updating last_sign_in_at: %w", err)
	}
	return nil
}

// FindUserByID retrieves a user record by unique ID across tenant clients.
func (r *Repository) FindUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, "", "")
	u, err := client.User.Query().
		Where(user.ID(userID)).
		Only(ctx)

	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying user by ID %s: %w", userID, err)
	}
	return u, nil
}

// EnsureDefaultApplicationExists checks if an Application exists and creates a default record if missing.
func (r *Repository) EnsureDefaultApplicationExists(ctx context.Context, appID string, tenantID string, redirectURIs []string) error {
	client := r.factory.GetClient(ctx, tenantID, "test")
	exists, err := client.Application.Query().Where(application.ID(appID)).Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed checking application existence: %w", err)
	}
	if !exists {
		_, err := client.Application.Create().
			SetID(appID).
			SetTenantID(tenantID).
			SetName("Default Client App").
			SetEnvironment(application.EnvironmentTest).
			SetExactRedirectUris(redirectURIs).
			Save(ctx)
		if err != nil && !ent.IsConstraintError(err) {
			return fmt.Errorf("failed auto-creating application %s: %w", appID, err)
		}
	}
	return nil
}

// FindApplicationByID retrieves an Application record by client_id.
func (r *Repository) FindApplicationByID(ctx context.Context, appID string) (*ent.Application, error) {
	client := r.factory.GetClient(ctx, "", "")
	app, err := client.Application.Query().
		Where(application.ID(appID)).
		Only(ctx)

	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying application by ID %s: %w", appID, err)
	}
	return app, nil
}

// SetUserEmailVerificationToken saves the hashed single-use verification token and expiration.
func (r *Repository) SetUserEmailVerificationToken(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.User.UpdateOneID(userID).
		SetEmailVerificationToken(tokenHash).
		SetEmailVerificationExpiresAt(expiresAt).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed setting email verification token for user %s: %w", userID, err)
	}
	return nil
}

// FindUserByEmailVerificationToken finds a user record with a matching active verification token hash.
func (r *Repository) FindUserByEmailVerificationToken(ctx context.Context, tokenHash string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, "", "")
	u, err := client.User.Query().
		Where(
			user.EmailVerificationToken(tokenHash),
			user.EmailVerificationExpiresAtGT(time.Now()),
		).
		Only(ctx)

	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying user by verification token: %w", err)
	}
	return u, nil
}

// MarkUserEmailVerified updates email_verified = true and clears verification token fields.
func (r *Repository) MarkUserEmailVerified(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.User.UpdateOneID(userID).
		SetEmailVerified(true).
		ClearEmailVerificationToken().
		ClearEmailVerificationExpiresAt().
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed marking user %s email verified: %w", userID, err)
	}
	return nil
}

// SetUserMagicLinkToken saves the hashed single-use magic link token and expiration.
func (r *Repository) SetUserMagicLinkToken(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.User.UpdateOneID(userID).
		SetMagicLinkToken(tokenHash).
		SetMagicLinkExpiresAt(expiresAt).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed setting magic link token for user %s: %w", userID, err)
	}
	return nil
}

// FindUserByMagicLinkToken finds a user record with a matching active magic link token hash.
func (r *Repository) FindUserByMagicLinkToken(ctx context.Context, tokenHash string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, "", "")
	u, err := client.User.Query().
		Where(
			user.MagicLinkToken(tokenHash),
			user.MagicLinkExpiresAtGT(time.Now()),
		).
		Only(ctx)

	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying user by magic link token: %w", err)
	}
	return u, nil
}

// ClearUserMagicLinkToken clears active magic link token fields for a user.
func (r *Repository) ClearUserMagicLinkToken(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.User.UpdateOneID(userID).
		ClearMagicLinkToken().
		ClearMagicLinkExpiresAt().
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed clearing magic link token for user %s: %w", userID, err)
	}
	return nil
}

// CreateOrUpdatePendingTOTPSecret creates or updates a TOTP secret for a user with is_enabled explicitly set to false.
func (r *Repository) CreateOrUpdatePendingTOTPSecret(ctx context.Context, id string, userID string, encryptedSecret string) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	existing, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeTotp),
		).
		Only(ctx)

	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("failed querying existing TOTP method: %w", err)
	}

	if existing != nil {
		updated, err := client.TwoFactorMethod.UpdateOneID(existing.ID).
			SetSecretEncrypted(encryptedSecret).
			SetIsEnabled(false). // EXPLICITLY set to false on pending update
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed updating pending TOTP method: %w", err)
		}
		return updated, nil
	}

	created, err := client.TwoFactorMethod.Create().
		SetID(id).
		SetUserID(userID).
		SetType(twofactormethod.TypeTotp).
		SetSecretEncrypted(encryptedSecret).
		SetIsEnabled(false). // EXPLICITLY set to false on pending insert
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating pending TOTP method: %w", err)
	}
	return created, nil
}

// GetTOTPMethodForUser retrieves any TOTP method record (pending or active) for a user.
func (r *Repository) GetTOTPMethodForUser(ctx context.Context, userID string) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	tfm, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeTotp),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying TOTP method for user: %w", err)
	}
	return tfm, nil
}

// GetActiveTOTPMethodForUser retrieves an active (is_enabled = true) TOTP method for a user.
func (r *Repository) GetActiveTOTPMethodForUser(ctx context.Context, userID string) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	tfm, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeTotp),
			twofactormethod.IsEnabled(true),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying active TOTP method for user: %w", err)
	}
	return tfm, nil
}

// EnableTwoFactorMethod updates is_enabled = true for a 2FA method.
func (r *Repository) EnableTwoFactorMethod(ctx context.Context, methodID string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.TwoFactorMethod.UpdateOneID(methodID).
		SetIsEnabled(true).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed enabling 2FA method: %w", err)
	}
	return nil
}

// UpdateTwoFactorMethodLastUsed updates last_used_at timestamp.
func (r *Repository) UpdateTwoFactorMethodLastUsed(ctx context.Context, methodID string) error {
	client := r.factory.GetClient(ctx, "", "")
	now := time.Now()
	_, err := client.TwoFactorMethod.UpdateOneID(methodID).
		SetLastUsedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed updating 2FA method last_used_at: %w", err)
	}
	return nil
}

// DeleteTwoFactorMethod deletes a 2FA method by ID.
func (r *Repository) DeleteTwoFactorMethod(ctx context.Context, methodID string) error {
	client := r.factory.GetClient(ctx, "", "")
	err := client.TwoFactorMethod.DeleteOneID(methodID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed deleting 2FA method: %w", err)
	}
	return nil
}

// DeleteAllRecoveryCodesForUser deletes all existing backup_code TwoFactorMethod records for a user.
func (r *Repository) DeleteAllRecoveryCodesForUser(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.TwoFactorMethod.Delete().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeBackupCode),
		).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed deleting existing recovery codes: %w", err)
	}
	return nil
}

// CreateBatchRecoveryCodes inserts a set of backup recovery codes for a user.
// Note for type="backup_code": secret_encrypted stores an Argon2id one-way password hash (RFC 9106 t=3, m=64MB, p=4), NOT reversible encrypted data.
func (r *Repository) CreateBatchRecoveryCodes(ctx context.Context, userID string, argon2Hashes []string) error {
	client := r.factory.GetClient(ctx, "", "")
	bulk := make([]*ent.TwoFactorMethodCreate, len(argon2Hashes))
	for i, hash := range argon2Hashes {
		tfmID := fmt.Sprintf("tfm_%s", uuid.New().String()[:12])
		bulk[i] = client.TwoFactorMethod.Create().
			SetID(tfmID).
			SetUserID(userID).
			SetType(twofactormethod.TypeBackupCode).
			SetSecretEncrypted(hash).
			SetIsEnabled(true)
	}
	_, err := client.TwoFactorMethod.CreateBulk(bulk...).Save(ctx)
	if err != nil {
		return fmt.Errorf("failed saving batch recovery codes: %w", err)
	}
	return nil
}

// GetRecoveryCodesForUser retrieves all recovery code records (used and unused) for a user.
// Note for type="backup_code": secret_encrypted stores an Argon2id one-way password hash (RFC 9106 t=3, m=64MB, p=4), NOT reversible encrypted data.
func (r *Repository) GetRecoveryCodesForUser(ctx context.Context, userID string) ([]*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	codes, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeBackupCode),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed querying recovery codes for user: %w", err)
	}
	return codes, nil
}

// GetActiveRecoveryCodeCountForUser counts remaining unused recovery codes (is_enabled = true) for a user.
func (r *Repository) GetActiveRecoveryCodeCountForUser(ctx context.Context, userID string) (int, error) {
	client := r.factory.GetClient(ctx, "", "")
	count, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeBackupCode),
			twofactormethod.IsEnabled(true),
		).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed counting unused recovery codes: %w", err)
	}
	return count, nil
}

// MarkRecoveryCodeConsumed marks a specific recovery code as used (is_enabled = false).
func (r *Repository) MarkRecoveryCodeConsumed(ctx context.Context, methodID string) error {
	client := r.factory.GetClient(ctx, "", "")
	now := time.Now()
	_, err := client.TwoFactorMethod.UpdateOneID(methodID).
		SetIsEnabled(false).
		SetLastUsedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed marking recovery code consumed: %w", err)
	}
	return nil
}

// CreateWebAuthnPasskey creates a new WebAuthn passkey TwoFactorMethod record for a user.
// Note for type="passkey": secret_encrypted is left NULL/unused; public key, credential_id, sign_count, and webauthn_metadata are stored in dedicated fields.
func (r *Repository) CreateWebAuthnPasskey(ctx context.Context, userID string, name string, credentialID string, publicKey []byte, signCount uint32, metadata map[string]interface{}) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	tfmID := fmt.Sprintf("tfm_%s", uuid.New().String()[:12])
	if name == "" {
		name = "Passkey Authenticator"
	}
	passkey, err := client.TwoFactorMethod.Create().
		SetID(tfmID).
		SetUserID(userID).
		SetType(twofactormethod.TypePasskey).
		SetName(name).
		SetCredentialID(credentialID).
		SetPublicKey(publicKey).
		SetSignCount(signCount).
		SetWebauthnMetadata(metadata).
		SetIsEnabled(true).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating WebAuthn passkey: %w", err)
	}
	return passkey, nil
}

// GetPasskeyByCredentialID retrieves a passkey TwoFactorMethod record by credential ID.
func (r *Repository) GetPasskeyByCredentialID(ctx context.Context, credentialID string) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	tfm, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.TypeEQ(twofactormethod.TypePasskey),
			twofactormethod.CredentialIDEQ(credentialID),
			twofactormethod.IsEnabled(true),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying passkey by credential ID: %w", err)
	}
	return tfm, nil
}

// GetPasskeysForUser retrieves all active passkeys for a user.
func (r *Repository) GetPasskeysForUser(ctx context.Context, userID string) ([]*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	passkeys, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypePasskey),
			twofactormethod.IsEnabled(true),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed querying passkeys for user: %w", err)
	}
	return passkeys, nil
}

// UpdatePasskeySignCount updates sign_count and last_used_at timestamp for a WebAuthn passkey.
func (r *Repository) UpdatePasskeySignCount(ctx context.Context, methodID string, newSignCount uint32) error {
	client := r.factory.GetClient(ctx, "", "")
	now := time.Now()
	_, err := client.TwoFactorMethod.UpdateOneID(methodID).
		SetSignCount(newSignCount).
		SetLastUsedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed updating passkey sign count: %w", err)
	}
	return nil
}

// CountActivePrimary2FAMethods counts active non-recovery-code 2FA methods (TOTP + Passkeys + SMS) for a user.
func (r *Repository) CountActivePrimary2FAMethods(ctx context.Context, userID string) (int, error) {
	client := r.factory.GetClient(ctx, "", "")
	count, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.IsEnabled(true),
			twofactormethod.TypeIn(twofactormethod.TypeTotp, twofactormethod.TypePasskey, twofactormethod.TypeSms),
		).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed counting active primary 2FA methods: %w", err)
	}
	return count, nil
}

// CreateOrUpdatePendingSMSMethod creates or updates an SMS TwoFactorMethod record for a user with is_enabled = false.
func (r *Repository) CreateOrUpdatePendingSMSMethod(ctx context.Context, userID string, encryptedPhone string) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	existing, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeSms),
		).
		Only(ctx)
	if err == nil && existing != nil {
		updated, err := client.TwoFactorMethod.UpdateOneID(existing.ID).
			SetSecretEncrypted(encryptedPhone).
			SetIsEnabled(false). // MUST explicitly set is_enabled: false on insert/update so unconfirmed enrollment cannot be counted as active
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed updating pending SMS 2FA method: %w", err)
		}
		return updated, nil
	}

	methodID := fmt.Sprintf("2fa_%s", uuid.New().String()[:12])
	created, err := client.TwoFactorMethod.Create().
		SetID(methodID).
		SetUserID(userID).
		SetType(twofactormethod.TypeSms).
		SetName("SMS OTP").
		SetSecretEncrypted(encryptedPhone).
		SetIsEnabled(false). // MUST explicitly set is_enabled: false on insert so unconfirmed enrollment cannot be counted as active
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating pending SMS 2FA method: %w", err)
	}
	return created, nil
}

// GetActiveSMSMethodForUser retrieves an active (is_enabled = true) SMS method for a user.
func (r *Repository) GetActiveSMSMethodForUser(ctx context.Context, userID string) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	tfm, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeSms),
			twofactormethod.IsEnabled(true),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying active SMS method for user: %w", err)
	}
	return tfm, nil
}

// GetSMSMethodForUser retrieves any SMS method (active or pending) for a user.
func (r *Repository) GetSMSMethodForUser(ctx context.Context, userID string) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	tfm, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.TypeEQ(twofactormethod.TypeSms),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying SMS method for user: %w", err)
	}
	return tfm, nil
}

// UpdateUserPhone updates the user's phone_number and phone_verified status.
func (r *Repository) UpdateUserPhone(ctx context.Context, userID string, phoneNumber string, verified bool) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.User.UpdateOneID(userID).
		SetPhoneNumber(phoneNumber).
		SetPhoneVerified(verified).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed updating user phone number: %w", err)
	}
	return nil
}

// CreateRecoveryContact creates a new guardian record.
func (r *Repository) CreateRecoveryContact(ctx context.Context, userID, email, name string, shareIndex int, shareHash, inviteHash string, expiresAt time.Time) (*ent.RecoveryContact, error) {
	client := r.factory.GetClient(ctx, "", "")
	id := fmt.Sprintf("gdn_%s", uuid.New().String()[:12])
	contact, err := client.RecoveryContact.Create().
		SetID(id).
		SetUserID(userID).
		SetGuardianEmail(email).
		SetGuardianName(name).
		SetShareIndex(shareIndex).
		SetShareHash(shareHash).
		SetStatus(recoverycontact.StatusPendingInvite).
		SetInvitationTokenHash(inviteHash).
		SetInvitationExpiresAt(expiresAt).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating recovery contact: %w", err)
	}
	return contact, nil
}

// GetRecoveryContactsByUser lists all guardians enrolled by a user.
func (r *Repository) GetRecoveryContactsByUser(ctx context.Context, userID string) ([]*ent.RecoveryContact, error) {
	client := r.factory.GetClient(ctx, "", "")
	contacts, err := client.RecoveryContact.Query().
		Where(recoverycontact.UserID(userID)).
		Order(ent.Asc(recoverycontact.FieldShareIndex)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed querying recovery contacts for user: %w", err)
	}
	return contacts, nil
}

// GetActiveRecoveryContactsByUser lists only active guardians enrolled by a user.
func (r *Repository) GetActiveRecoveryContactsByUser(ctx context.Context, userID string) ([]*ent.RecoveryContact, error) {
	client := r.factory.GetClient(ctx, "", "")
	contacts, err := client.RecoveryContact.Query().
		Where(
			recoverycontact.UserID(userID),
			recoverycontact.StatusEQ(recoverycontact.StatusActive),
		).
		Order(ent.Asc(recoverycontact.FieldShareIndex)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed querying active recovery contacts for user: %w", err)
	}
	return contacts, nil
}

// GetRecoveryContactByID fetches a guardian by contact ID.
func (r *Repository) GetRecoveryContactByID(ctx context.Context, contactID string) (*ent.RecoveryContact, error) {
	client := r.factory.GetClient(ctx, "", "")
	contact, err := client.RecoveryContact.Query().
		Where(recoverycontact.ID(contactID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying recovery contact %s: %w", contactID, err)
	}
	return contact, nil
}

// UpdateRecoveryContactStatus updates the status of a guardian (e.g. pending_invite -> active).
func (r *Repository) UpdateRecoveryContactStatus(ctx context.Context, contactID string, status recoverycontact.Status) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.RecoveryContact.UpdateOneID(contactID).
		SetStatus(status).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed updating recovery contact status: %w", err)
	}
	return nil
}

// DeleteRecoveryContact deletes or revokes a guardian record.
func (r *Repository) DeleteRecoveryContact(ctx context.Context, contactID string) error {
	client := r.factory.GetClient(ctx, "", "")
	err := client.RecoveryContact.DeleteOneID(contactID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed deleting recovery contact %s: %w", contactID, err)
	}
	return nil
}

// UpdateRecoveryContactShare updates the share_index and share_hash of an existing guardian during re-split.
func (r *Repository) UpdateRecoveryContactShare(ctx context.Context, contactID string, shareIndex int, shareHash string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.RecoveryContact.UpdateOneID(contactID).
		SetShareIndex(shareIndex).
		SetShareHash(shareHash).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed updating guardian share index and hash: %w", err)
	}
	return nil
}

// CreateRecoveryRequest creates a new recovery request record.
func (r *Repository) CreateRecoveryRequest(ctx context.Context, userID, ip, subnet, userAgent string, isTrustedOrigin bool, cancelHash string) (*ent.RecoveryRequest, error) {
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Unknown)"
	}
	client := r.factory.GetClient(ctx, "", "")
	id := fmt.Sprintf("req_%s", uuid.New().String()[:12])
	req, err := client.RecoveryRequest.Create().
		SetID(id).
		SetUserID(userID).
		SetInitiatedFromIP(ip).
		SetInitiatedFromSubnet(subnet).
		SetInitiatedFromUserAgent(userAgent).
		SetIsTrustedDeviceOrigin(isTrustedOrigin).
		SetStatus(recoveryrequest.StatusInitiated).
		SetCancellationTokenHash(cancelHash).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating recovery request: %w", err)
	}
	return req, nil
}

// GetRecoveryRequestByID queries a recovery request by ID.
func (r *Repository) GetRecoveryRequestByID(ctx context.Context, requestID string) (*ent.RecoveryRequest, error) {
	client := r.factory.GetClient(ctx, "", "")
	req, err := client.RecoveryRequest.Query().
		Where(recoveryrequest.ID(requestID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying recovery request %s: %w", requestID, err)
	}
	return req, nil
}

// UpdateRecoveryRequestStatus updates the state machine status and optional method of a recovery request.
func (r *Repository) UpdateRecoveryRequestStatus(ctx context.Context, requestID string, status recoveryrequest.Status) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.RecoveryRequest.UpdateOneID(requestID).
		SetStatus(status).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed updating recovery request status: %w", err)
	}
	return nil
}

// GetRecoveryRequestByCancellationHash retrieves an active recovery request by its cancellation token hash.
func (r *Repository) GetRecoveryRequestByCancellationHash(ctx context.Context, cancelHash string) (*ent.RecoveryRequest, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.RecoveryRequest.Query().
		Where(recoveryrequest.CancellationTokenHashEQ(cancelHash)).
		Only(ctx)
}

// CreateSecurityBlacklist creates a 7-day blacklist entry for an originating IP, subnet, or fingerprint.
func (r *Repository) CreateSecurityBlacklist(ctx context.Context, tenantID, userID, ipAddress, subnet, fpHash, reason string, expiresAt time.Time) (*ent.SecurityBlacklist, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")
	id := fmt.Sprintf("blk_%s", uuid.New().String()[:12])
	return client.SecurityBlacklist.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetUserID(userID).
		SetIPAddress(ipAddress).
		SetSubnet(subnet).
		SetFingerprintHash(fpHash).
		SetReason(reason).
		SetExpiresAt(expiresAt).
		Save(ctx)
}

// IsOriginBlacklisted checks if the given user ID and IP/subnet/fingerprint are currently blacklisted.
func (r *Repository) IsOriginBlacklisted(ctx context.Context, tenantID, userID, ipAddress, subnet, fpHash string) (bool, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")
	now := time.Now()

	predicates := []predicate.SecurityBlacklist{
		securityblacklist.UserID(userID),
		securityblacklist.ExpiresAtGT(now),
	}

	orPreds := []predicate.SecurityBlacklist{}
	if ipAddress != "" {
		orPreds = append(orPreds, securityblacklist.IPAddress(ipAddress))
	}
	if subnet != "" {
		orPreds = append(orPreds, securityblacklist.Subnet(subnet))
	}
	if fpHash != "" {
		orPreds = append(orPreds, securityblacklist.FingerprintHash(fpHash))
	}

	if len(orPreds) == 0 {
		return false, nil
	}

	predicates = append(predicates, securityblacklist.Or(orPreds...))

	exists, err := client.SecurityBlacklist.Query().
		Where(predicates...).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed checking security blacklist: %w", err)
	}

	return exists, nil
}

// RevokeUserSessionsExcept revokes all active sessions for a user, excluding exceptSessionID if non-empty.
func (r *Repository) RevokeUserSessionsExcept(ctx context.Context, userID string, exceptSessionID string) (int, error) {
	client := r.factory.GetClient(ctx, "", "")
	query := client.Session.Query().
		Where(
			session.UserID(userID),
			session.StatusEQ(session.StatusActive),
		)
	if exceptSessionID != "" {
		query = query.Where(session.IDNEQ(exceptSessionID))
	}

	sessionsToRevoke, err := query.All(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed querying sessions to revoke: %w", err)
	}

	revokedCount := 0
	for _, s := range sessionsToRevoke {
		err := client.Session.UpdateOne(s).
			SetStatus(session.StatusRevoked).
			Exec(ctx)
		if err == nil {
			revokedCount++
		}
	}

	return revokedCount, nil
}

// FlagUserForSecurityReview sets security_review_required = true for a user.
func (r *Repository) FlagUserForSecurityReview(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.UpdateOneID(userID).
		SetSecurityReviewRequired(true).
		Exec(ctx)
}




