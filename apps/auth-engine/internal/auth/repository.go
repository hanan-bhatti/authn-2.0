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

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
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
