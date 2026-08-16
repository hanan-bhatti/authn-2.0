/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/repository.go
 * Tier: Internal Feature Package / Auth Repository
 *
 * Description: Ent-backed data access for the authentication domain — users,
 *              tenants, applications, API keys, sessions, two-factor methods,
 *              account-recovery contacts and requests, security blacklists, and
 *              audit logs. Methods hold no business logic: they translate a call
 *              into a single Ent query or mutation and normalize its error. Tenant
 *              and environment isolation is NOT applied here — it is enforced by
 *              the Ent privacy interceptors from the PrivacyContext carried on ctx,
 *              so a ctx without tenant scope fails closed with a privacy violation
 *              rather than reading across tenants. The tenantID/env arguments passed
 *              to GetClient only select a connection pool. Lookup methods follow a
 *              (nil, nil) "not found" convention; the exceptions are called out on
 *              each method.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"time"

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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// Repository is the auth domain's data access layer. It is stateless beyond its
// client factory and safe for concurrent use by multiple request goroutines.
type Repository struct {
	// factory resolves the Ent client for a (tenant, environment) connection pool,
	// falling back to the shared default client. Held rather than a bare *ent.Client
	// so per-tenant pool routing stays a property of the call, not of the repository.
	factory *clientfactory.ClientFactory
}

// NewRepository returns a Repository bound to factory. The factory is used as
// given and is not validated; a nil factory panics on first query, not here.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// GetClientFactory exposes the underlying client factory so callers can reach
// entities this repository does not wrap, and so services can open transactions.
// Callers that use it take on responsibility for supplying a tenant-scoped ctx,
// since the privacy interceptors read scope from ctx and not from the client.
func (r *Repository) GetClientFactory() *clientfactory.ClientFactory {
	return r.factory
}

// GetUserByID loads a user by primary key.
//
// Unlike FindUserByID, a missing row is an error: the raw *ent.NotFoundError is
// returned unwrapped, so callers must test it with ent.IsNotFound rather than
// checking for a nil user. A privacy violation error means ctx carried no tenant
// scope, or the row belongs to a different tenant.
func (r *Repository) GetUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}

// EmailVerified reports whether userID's email address is verified, and whether
// the account exists at all.
//
// The two are reported separately because the caller — middleware.RequirePlatformAuth
// — answers differently for each: an account that no longer exists invalidates
// the session, while an unverified one is a live session that has not finished
// signing up. Returning a bare false for both would give the wrong status to
// whichever case was folded into the other.
//
// The query is tenant-scoped through ctx like any other read, so a user ID that
// belongs to a different tenant reports found=false rather than that tenant's
// verification state.
func (r *Repository) EmailVerified(ctx context.Context, userID string) (bool, bool, error) {
	u, err := r.factory.GetClient(ctx, "", "").User.Query().
		Where(user.ID(userID)).
		Select(user.FieldEmailVerified).
		Only(ctx)
	if ent.IsNotFound(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("failed reading email verification state: %w", err)
	}
	return u.EmailVerified, true, nil
}

// TenantExists reports whether tenantID names a provisioned tenant.
//
// The probe runs under a bypass because it answers a question that precedes
// tenant scoping: a scoped query would filter by the very tenant whose
// existence is in doubt. It reads nothing but the presence of one row.
//
// Returns an error only when the query fails; a missing tenant is (false, nil).
func (r *Repository) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	if tenantID == "" {
		return false, nil
	}
	sysCtx := privacy.NewBypassContext(ctx)
	exists, err := r.factory.GetClient(sysCtx, tenantID, "test").Tenant.Query().
		Where(tenant.ID(tenantID)).
		Exist(sysCtx)
	if err != nil {
		return false, fmt.Errorf("failed checking tenant existence: %w", err)
	}
	return exists, nil
}

// EnsureTenantExists creates tenantID as a default workspace if no such tenant
// row exists, and is a no-op when one already does.
//
// This is for test fixtures and bootstrap binaries only, and is deliberately
// not reachable from the request path: a signup naming an unknown tenant is
// refused rather than silently creating one. A tenant made here has no roles,
// no application and no keys, so it is not a substitute for provisioning.
//
// Returns an error only if the existence probe fails or the insert fails for a
// reason other than a uniqueness conflict; a conflict means a concurrent caller
// won the same race and the postcondition ("the tenant exists") already holds.
func (r *Repository) EnsureTenantExists(ctx context.Context, tenantID string) error {
	// The bypass context suppresses tenant scoping because this row is what
	// establishes the tenant: no scoped query could match it before it exists.
	sysCtx := privacy.NewBypassContext(ctx)
	client := r.factory.GetClient(sysCtx, tenantID, "test")
	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(sysCtx)
	if err != nil {
		return fmt.Errorf("failed checking tenant existence: %w", err)
	}
	if !exists {
		_, err := client.Tenant.Create().
			SetID(tenantID).
			SetName("Default Workspace").
			SetSlug(tenantID).
			Save(sysCtx)
		if err != nil && !ent.IsConstraintError(err) {
			return fmt.Errorf("failed auto-creating tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

// FindUserByEmail resolves an email to a user within one tenant and environment.
//
// Returns nil, nil when no row matches — callers must treat a nil user as
// "no such account", not as an error, and on the sign-in path must keep the
// nil-user and wrong-password branches indistinguishable to the client to avoid
// turning this lookup into an account-enumeration oracle.
//
// The predicates restate the tenant and environment filters that the privacy
// interceptor also applies, so the query is correct even under a bypass context.
// A non-nil error is a query or privacy-scope failure, never "not found".
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

// CreateUser inserts a user row and returns it.
//
// passwordHash is expected to be an Argon2id encoded hash; name may be empty.
// (tenantID, env, email) is unique, so a duplicate signup surfaces as a wrapped
// ent constraint error — callers that race on registration should treat a
// constraint error as "already registered" rather than a server fault.
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

// ClaimFirstAdminRole atomically claims the one-time first-admin slot for a tenant.
//
// It issues a conditional UPDATE:
//
//	UPDATE tenants SET first_admin_claimed = true
//	WHERE id = ? AND first_admin_claimed = false
//
// The database serializes the false → true transition, so exactly one of any set
// of concurrent callers observes one affected row. That caller is the tenant's
// first user and is granted role="tenant_admin"; every other caller observes zero
// rows and gets role="". Correctness rests on the predicate being evaluated inside
// the UPDATE — reading the flag first and writing it after would reopen a TOCTOU
// window in which two concurrent signups both become admin.
//
// Returns true only for the winning caller. An error means the claim outcome is
// unknown, and the caller must not grant admin.
func (r *Repository) ClaimFirstAdminRole(ctx context.Context, tenantID string) (bool, error) {
	client := r.factory.GetClient(ctx, tenantID, "test") // tenant rows are not environment-scoped
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

// FindApiKeyByHash looks up an API key by the exact value stored in key_hash —
// a peppered HMAC-SHA256 digest for secret keys, or the literal key string for
// publishable keys. The caller must hash before calling; no hashing happens here.
//
// Returns nil, nil when no key matches, which callers must render as an
// authentication failure rather than a server error.
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

// CreateSession records a new active login session and returns it.
//
// tokenHash is the SHA-256 digest of the opaque refresh token; the token itself
// is never persisted, so a database compromise does not yield usable refresh
// tokens. refresh_token_hash is unique, so reusing a digest is a constraint error.
// An error means no session exists and the caller must not issue tokens for it.
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

// RevokeAllSessionsForUser revokes every session for a user that is not already
// revoked — active sessions and sessions still inside their rotation grace window
// alike, so a token mid-rotation cannot survive the revocation.
//
// Used for password change, credential compromise, and account lockout. An error
// means revocation may not have taken effect and the caller must not report the
// account as secured.
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

// FindSessionByTokenHash resolves a presented refresh token, already SHA-256
// hashed by the caller, to its session. The hash column is unique, so at most one
// row can match.
//
// Returns nil, nil when no session matches; the caller must treat that as an
// invalid or already-rotated token, not as an error. The returned session may be
// expired, revoked, or in rotated_grace — status and expiry are the caller's
// checks to make, not this method's.
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

// FindSessionByID loads a session by primary key.
//
// Returns nil, nil when no session matches. The row is returned regardless of
// status or expiry, so callers must validate both before honoring it.
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

// MarkSessionRotatedWithGrace retires oldSessionID into rotated_grace, links it
// to its successor, and stamps a grace deadline graceDuration from now.
//
// The grace window exists so a client whose rotation response was lost in flight
// can retry with the superseded token instead of being logged out. The window is
// also what makes replay detectable: a superseded token presented after the
// deadline, or a second time, identifies a stolen token rather than a lost
// response, and the caller is expected to revoke the session family.
//
// Errors if oldSessionID does not exist. An error leaves the old session active,
// so two live tokens would exist for one session — callers must fail the rotation
// rather than issue the new token.
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

// CreateAuditLog appends an immutable security audit record attributed to a user
// actor.
//
// tenantID is required: audit rows are tenant-scoped, so an empty tenantID is
// rejected by the privacy layer and the event is not recorded. Callers that
// discard this error trade the audit trail for request latency; that is only
// acceptable where the audited action is itself already durable.
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

// UpdateUserLastSignIn stamps last_sign_in_at with the current server time.
//
// Errors if the user does not exist. The value is presentational and feeds
// dormant-account reporting; a failure here should not fail an otherwise
// successful sign-in.
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

// FindUserByID loads a user by primary key.
//
// Returns nil, nil when no row matches — a nil user means "not found", not an
// error. This is the not-found-tolerant counterpart to GetUserByID, which
// returns ent's NotFoundError instead; prefer this one on paths where a missing
// user is an expected outcome.
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

// EnsureDefaultApplicationExists creates appID as a default test-environment
// OAuth client with the given exact redirect URIs if it does not already exist,
// and is a no-op when it does. Intended for test fixtures and local bootstrap
// binaries; it seeds redirect URIs without review, so it must not be reachable
// from a request path.
//
// A uniqueness conflict is treated as success, since a concurrent caller has
// already satisfied the postcondition.
func (r *Repository) EnsureDefaultApplicationExists(ctx context.Context, appID string, tenantID string, redirectURIs []string) error {
	// Bootstrap runs before any request-scoped tenant context exists, so scoping
	// is bypassed; tenant ownership is instead pinned explicitly by SetTenantID.
	sysCtx := privacy.NewBypassContext(ctx)
	client := r.factory.GetClient(sysCtx, tenantID, "test")
	exists, err := client.Application.Query().Where(application.ID(appID)).Exist(sysCtx)
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
			Save(sysCtx)
		if err != nil && !ent.IsConstraintError(err) {
			return fmt.Errorf("failed auto-creating application %s: %w", appID, err)
		}
	}
	return nil
}

// FindApplicationByID loads an OAuth client by its client_id.
//
// Returns nil, nil when no application matches — callers on the authorize
// endpoint must reject the request outright on a nil application and must not
// fall back to a default client, since the returned record carries the redirect
// URI allow-list that bounds where authorization codes may be delivered.
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

// CreateApplication registers an OAuth client with an exact-match redirect URI
// allow-list. The URIs and CORS origins are stored verbatim: validation and
// normalization belong to the caller, and anything accepted here is later
// honored as a redirect target or a browser-origin grant.
//
// env is "test" or "live"; an empty value takes the schema default of "test".
// redirectURIs and corsOrigins may be empty — an empty CORS list means "not
// configured", leaving origin checks to the deployment-wide policy.
//
// Returns the raw ent error unwrapped, unlike most methods in this file, so a
// duplicate client_id arrives as an *ent.ConstraintError.
func (r *Repository) CreateApplication(ctx context.Context, id, tenantID, name, env string, redirectURIs, corsOrigins []string) (*ent.Application, error) {
	client := r.factory.GetClient(ctx, tenantID, env)
	builder := client.Application.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetName(name).
		SetExactRedirectUris(redirectURIs)
	if env != "" {
		builder = builder.SetEnvironment(application.Environment(env))
	}
	if len(corsOrigins) > 0 {
		builder = builder.SetAllowedCorsOrigins(corsOrigins)
	}
	return builder.Save(ctx)
}

// ListApplications returns every application in the caller's tenant.
//
// The tenant is not a parameter: the privacy interceptor scopes the query to
// whatever tenant the request context carries, so this cannot be pointed at
// another tenant's applications by passing a different ID. Results are ordered
// by creation time, oldest first, so a console list is stable across calls.
func (r *Repository) ListApplications(ctx context.Context) ([]*ent.Application, error) {
	client := r.factory.GetClient(ctx, "", "")
	apps, err := client.Application.Query().
		Order(ent.Asc(application.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed listing applications: %w", err)
	}
	return apps, nil
}

// GetApplicationByIDScoped loads one application, but only within the caller's
// tenant.
//
// Unlike FindApplicationByID — which the authorize endpoint uses and which must
// resolve a client_id regardless of scope — this is the read behind the admin
// CRUD, so it is tenant-scoped by the interceptor. A cross-tenant ID is
// therefore indistinguishable from an absent one: both return nil, nil, and the
// caller answers 404 either way, never revealing that the ID exists elsewhere.
func (r *Repository) GetApplicationByIDScoped(ctx context.Context, id string) (*ent.Application, error) {
	client := r.factory.GetClient(ctx, "", "")
	app, err := client.Application.Query().
		Where(application.ID(id)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying application %s: %w", id, err)
	}
	return app, nil
}

// UpdateApplication changes an application's mutable fields within the caller's
// tenant, and returns the updated row, or nil when no such application exists in
// this tenant.
//
// The scoped read is load-bearing, not a convenience: the write hook stamps
// tenant_id on inserts but adds no tenant predicate to an UpdateOneID, whose SQL
// filters on id alone. Confirming ownership through a scoped query first — which
// the interceptor filters — is what stops one tenant editing another's
// application by guessing its ID. A nil pointer argument leaves that field
// unchanged; a non-nil one sets it, including to an empty slice to clear a list.
func (r *Repository) UpdateApplication(ctx context.Context, id string, name *string, redirectURIs, corsOrigins *[]string) (*ent.Application, error) {
	existing, err := r.GetApplicationByIDScoped(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, nil
	}

	upd := r.factory.GetClient(ctx, "", "").Application.UpdateOneID(id)
	if name != nil {
		upd = upd.SetName(*name)
	}
	if redirectURIs != nil {
		upd = upd.SetExactRedirectUris(*redirectURIs)
	}
	if corsOrigins != nil {
		upd = upd.SetAllowedCorsOrigins(*corsOrigins)
	}

	app, err := upd.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed updating application %s: %w", id, err)
	}
	return app, nil
}

// DeleteApplication removes an application within the caller's tenant, reporting
// whether a row was deleted.
//
// It performs the same scoped ownership read as UpdateApplication and for the
// same reason — DeleteOneID filters on id alone — so a cross-tenant ID deletes
// nothing and returns false rather than destroying another customer's
// application.
func (r *Repository) DeleteApplication(ctx context.Context, id string) (bool, error) {
	existing, err := r.GetApplicationByIDScoped(ctx, id)
	if err != nil {
		return false, err
	}
	if existing == nil {
		return false, nil
	}

	if err := r.factory.GetClient(ctx, "", "").Application.DeleteOneID(id).Exec(ctx); err != nil {
		return false, fmt.Errorf("failed deleting application %s: %w", id, err)
	}
	return true, nil
}

// SetUserEmailVerificationToken stores the hash of a single-use verification
// token together with its expiry, replacing any token already outstanding so a
// reissue invalidates the previous link.
//
// tokenHash must already be hashed; the plaintext token exists only in the email.
// Errors if the user does not exist.
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

// FindUserByEmailVerificationToken resolves an unexpired verification token hash
// to its user.
//
// Expiry is part of the predicate, so an expired token is indistinguishable from
// an unknown one: both yield nil, nil. Callers must not report which it was.
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

// MarkUserEmailVerified sets email_verified and clears the verification token and
// its expiry in the same statement, which is what makes the token single-use: the
// link cannot be replayed once redeemed.
//
// Errors if the user does not exist.
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

// SetUserMagicLinkToken stores the hash of a single-use magic link token and its
// expiry, overwriting any outstanding token so only the most recent link works.
//
// Errors if the user does not exist.
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

// FindUserByMagicLinkToken resolves an unexpired magic link token hash to its user.
//
// Expiry is enforced in the query, so expired and unknown tokens are both
// nil, nil and must be reported identically. A match authenticates the user
// outright, so the caller must consume the token via ClearUserMagicLinkToken
// before issuing a session.
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

// ClearUserMagicLinkToken consumes a magic link by clearing its hash and expiry.
//
// This is what enforces single use, so it must run before the session is issued;
// clearing afterwards leaves a replay window. Errors if the user does not exist.
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

// CreateOrUpdatePendingTOTPSecret stages a TOTP enrollment: it overwrites the
// user's existing TOTP row if one exists, otherwise inserts one under id.
//
// The stored method is always left disabled. Enrollment is only completed by
// EnableTwoFactorMethod after the user proves possession with a valid code, so a
// half-finished enrollment can never satisfy a 2FA challenge or count toward
// CountActivePrimary2FAMethods. Re-enrolling replaces the secret in place, which
// invalidates any authenticator provisioned from the previous secret.
//
// Errors if the lookup or write fails; (user_id, type) is not unique, so a user
// holding two TOTP rows yields an *ent.NotSingularError here.
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
			SetIsEnabled(false). // Set explicitly: re-enrollment must demote an already-enabled method back to pending.
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
		SetIsEnabled(false). // Set explicitly rather than relying on the column default.
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating pending TOTP method: %w", err)
	}
	return created, nil
}

// GetTOTPMethodForUser returns the user's TOTP method in any state, pending or
// enabled. Use it for enrollment flows; use GetActiveTOTPMethodForUser to decide
// whether a challenge is required.
//
// Returns nil, nil when the user has no TOTP method.
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

// GetActiveTOTPMethodForUser returns the user's confirmed TOTP method.
//
// The is_enabled predicate is the authorization boundary between a staged
// enrollment and a usable second factor: a pending row yields nil, nil here, so
// verification paths must use this method and never GetTOTPMethodForUser.
//
// Returns nil, nil when the user has no enabled TOTP method.
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

// EnableTwoFactorMethod promotes a staged 2FA method to active.
//
// This is the commit point of enrollment and must only be reached after the user
// has proven possession of the factor, since the method counts as a usable
// second factor immediately afterwards. Errors if methodID does not exist.
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

// UpdateTwoFactorMethodLastUsed stamps last_used_at on a 2FA method after a
// successful verification, feeding "last used" display and stale-factor cleanup.
//
// Errors if methodID does not exist. The value is advisory; a failure should not
// invalidate an already-successful verification.
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

// DeleteTwoFactorMethod removes a 2FA method row outright; there is no soft
// delete, so the secret or credential is unrecoverable afterwards.
//
// The row is addressed by ID alone and is not checked against an owning user, so
// the caller must confirm the method belongs to the authenticated user before
// calling, or a user could strip another account's second factor.
//
// Errors if methodID does not exist.
func (r *Repository) DeleteTwoFactorMethod(ctx context.Context, methodID string) error {
	client := r.factory.GetClient(ctx, "", "")
	err := client.TwoFactorMethod.DeleteOneID(methodID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed deleting 2FA method: %w", err)
	}
	return nil
}

// DeleteAllRecoveryCodesForUser removes every backup code a user holds, used and
// unused alike. It is the first half of regeneration and leaves the user with no
// recovery codes until CreateBatchRecoveryCodes runs, so the two must not be
// separated by anything that can fail independently.
//
// Deleting zero rows is not an error.
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

// CreateBatchRecoveryCodes inserts one backup_code row per hash in a single bulk
// statement, each marked enabled, i.e. unused. Row IDs are generated here, so the
// caller supplies hashes only.
//
// For type="backup_code", secret_encrypted holds an Argon2id one-way hash
// (RFC 9106, t=3, m=64MB, p=4), not reversible ciphertext: codes are verified by
// hashing the candidate, and a lost code cannot be recovered from the database.
// The plaintext codes exist only in the response shown to the user once.
//
// Errors leave no partial batch, since CreateBulk is a single statement.
func (r *Repository) CreateBatchRecoveryCodes(ctx context.Context, userID string, argon2Hashes []string) error {
	client := r.factory.GetClient(ctx, "", "")
	bulk := make([]*ent.TwoFactorMethodCreate, len(argon2Hashes))
	for i, hash := range argon2Hashes {
		tfmID := idgen.New("tfm")
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

// GetRecoveryCodesForUser returns every backup code row for a user, consumed and
// unconsumed, because verification must hash the candidate against each stored
// hash and consumption state is carried on the row (is_enabled).
//
// Returns an empty slice, not an error, when the user has none. secret_encrypted
// is an Argon2id one-way hash (RFC 9106, t=3, m=64MB, p=4), never plaintext, so
// these rows cannot be turned back into displayable codes.
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

// GetActiveRecoveryCodeCountForUser counts a user's unconsumed backup codes,
// which drives the "N codes remaining" warning and the prompt to regenerate.
//
// Returns 0 with a nil error when the user has none — zero is a valid answer,
// not a missing one.
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

// MarkRecoveryCodeConsumed burns a single backup code by clearing is_enabled and
// stamping last_used_at. The row is kept rather than deleted so the audit trail
// retains evidence that this specific code was redeemed.
//
// Clearing is_enabled is what enforces single use, so it must be committed before
// the recovery action is honored; a code redeemed twice would otherwise pass twice.
// Errors if methodID does not exist.
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

// CreateWebAuthnPasskey registers a WebAuthn credential as an immediately enabled
// 2FA method and returns it. The row ID is generated here; an empty name falls
// back to a generic label.
//
// For type="passkey", secret_encrypted is unused — the credential ID, COSE public
// key, signature counter, and attestation metadata live in their own columns, and
// the public key is not a secret. signCount is the authenticator's counter at
// registration and is the baseline that UpdatePasskeySignCount advances.
//
// Unlike TOTP and SMS, no separate confirmation step follows: the registration
// ceremony already proved possession, so the method is created enabled.
func (r *Repository) CreateWebAuthnPasskey(ctx context.Context, userID string, name string, credentialID string, publicKey []byte, signCount uint32, metadata map[string]interface{}) (*ent.TwoFactorMethod, error) {
	client := r.factory.GetClient(ctx, "", "")
	tfmID := idgen.New("tfm")
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

// GetPasskeyByCredentialID resolves the credential ID from an assertion to its
// enabled passkey. This is the lookup that decides which public key verifies the
// assertion signature, so it deliberately never matches a disabled credential.
//
// Returns nil, nil when no enabled passkey matches, which the caller must render
// as a failed assertion. credential_id carries no uniqueness constraint, so
// duplicate registrations surface as an *ent.NotSingularError rather than a match.
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

// GetPasskeysForUser returns a user's enabled passkeys, used to build the
// allowCredentials list for an assertion challenge and to render device lists.
//
// Returns an empty slice, not an error, when the user has none.
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

// UpdatePasskeySignCount persists the signature counter from a verified assertion
// and stamps last_used_at.
//
// The counter is the WebAuthn clone-detection signal: it must only ever advance,
// and the caller is responsible for rejecting an assertion whose counter did not
// increase before calling. This method writes newSignCount unconditionally and
// performs no comparison, so calling it with an unvalidated value destroys the
// baseline that makes cloning detectable.
//
// Errors if methodID does not exist.
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

// CountActivePrimary2FAMethods counts a user's enabled TOTP, passkey, and SMS
// methods.
//
// Backup codes are excluded by design: they are a fallback, not a factor a user
// may be left holding alone. Callers use this to refuse the removal of a user's
// last primary factor, so counting recovery codes here would let a user disable
// every real factor and still appear protected.
//
// Returns 0 with a nil error when the user has no primary factor enabled.
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

// CreateOrUpdatePendingSMSMethod stages an SMS second factor, overwriting the
// user's existing SMS row if one exists and inserting one otherwise. The row ID
// is generated here.
//
// encryptedPhone is reversible ciphertext, unlike the one-way hashes used for
// backup codes, because the number must be recoverable to send an OTP to it.
//
// The row is always left disabled: only GetActiveSMSMethodForUser is consulted
// during verification, so an unconfirmed number can neither receive a challenge
// nor count as a primary factor until the OTP is confirmed.
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
			SetIsEnabled(false). // Set explicitly: changing the number must demote a confirmed method back to pending.
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed updating pending SMS 2FA method: %w", err)
		}
		return updated, nil
	}

	methodID := idgen.New("2fa")
	created, err := client.TwoFactorMethod.Create().
		SetID(methodID).
		SetUserID(userID).
		SetType(twofactormethod.TypeSms).
		SetName("SMS OTP").
		SetSecretEncrypted(encryptedPhone).
		SetIsEnabled(false). // Set explicitly rather than relying on the column default.
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed creating pending SMS 2FA method: %w", err)
	}
	return created, nil
}

// GetActiveSMSMethodForUser returns the user's confirmed SMS method.
//
// The is_enabled predicate separates a confirmed number from one still awaiting
// OTP confirmation, so challenge and verification paths must use this rather than
// GetSMSMethodForUser — otherwise an attacker who set a pending number could have
// codes delivered to it.
//
// Returns nil, nil when the user has no enabled SMS method.
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

// GetSMSMethodForUser returns the user's SMS method in any state, pending or
// confirmed. It exists for enrollment and settings views; verification must use
// GetActiveSMSMethodForUser.
//
// Returns nil, nil when the user has no SMS method.
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

// UpdateUserPhone writes the user's phone number and its verified flag together.
//
// verified must only be true once possession has been proven by OTP: the flag is
// trusted downstream for SMS delivery and account recovery, and nothing here
// re-checks it. Errors if the user does not exist.
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

// CreateRecoveryContact enrolls a guardian in pending_invite state and returns
// the row. The contact ID is generated here.
//
// shareIndex and shareHash bind this guardian to one share of the user's split
// recovery secret: only the hash is stored, so the platform can verify a share a
// guardian later presents but cannot reconstruct the secret from the database.
// inviteHash is the hash of the invitation token mailed to the guardian, and
// expiresAt bounds how long that invitation can be accepted.
//
// The guardian cannot participate in recovery until the invitation is accepted
// and UpdateRecoveryContactStatus promotes the row to active.
func (r *Repository) CreateRecoveryContact(ctx context.Context, userID, email, name string, shareIndex int, shareHash, inviteHash string, expiresAt time.Time) (*ent.RecoveryContact, error) {
	client := r.factory.GetClient(ctx, "", "")
	id := idgen.New("gdn")
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

// GetRecoveryContactsByUser returns all guardians a user has enrolled, in any
// state, ordered by share index so the caller can map rows to share positions
// without re-sorting.
//
// Returns an empty slice, not an error, when the user has enrolled none.
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

// GetActiveRecoveryContactsByUser returns only guardians who have accepted their
// invitation, ordered by share index.
//
// This is the set that counts toward the recovery quorum: pending and revoked
// guardians hold no usable share, so quorum checks must use this rather than
// GetRecoveryContactsByUser or an unaccepted invitation would inflate the count.
//
// Returns an empty slice, not an error, when no guardian is active.
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

// GetRecoveryContactByID loads a guardian by contact ID.
//
// Returns nil, nil when no such contact exists. The row is addressed by ID alone
// with no owner predicate, so the caller must verify the contact belongs to the
// user in scope before acting on it.
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

// UpdateRecoveryContactStatus moves a guardian through its lifecycle, most often
// pending_invite → active on invitation acceptance.
//
// The transition is written unconditionally: no current status is asserted, so
// the caller owns the state machine and must not call this on a state where the
// transition is illegal. Errors if contactID does not exist.
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

// DeleteRecoveryContact removes a guardian row outright, destroying its share
// hash. Removing a guardian lowers the number of shares available, so the caller
// must re-split the secret across the remaining guardians or the quorum may
// become unreachable and lock the user out of recovery.
//
// Errors if contactID does not exist.
func (r *Repository) DeleteRecoveryContact(ctx context.Context, contactID string) error {
	client := r.factory.GetClient(ctx, "", "")
	err := client.RecoveryContact.DeleteOneID(contactID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed deleting recovery contact %s: %w", contactID, err)
	}
	return nil
}

// UpdateRecoveryContactShare rebinds a guardian to a new share position and hash
// after the recovery secret has been re-split.
//
// Every surviving guardian must be updated from the same split, since shares from
// different splits do not combine: a partial update leaves the quorum unable to
// reconstruct the secret. Errors if contactID does not exist.
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

// CreateRecoveryRequest opens an account recovery attempt in initiated state and
// returns it. The request ID is generated here.
//
// The originating IP, subnet, user agent, and trusted-device flag are captured at
// initiation and frozen: later policy decisions compare against these values, so
// they must reflect the request that started recovery and not a subsequent one.
// An empty user agent is replaced with a placeholder to keep the column populated
// for those comparisons.
//
// cancelHash is the hash of the cancellation token mailed to the account owner,
// which is what lets a legitimate owner abort a recovery they did not start.
func (r *Repository) CreateRecoveryRequest(ctx context.Context, userID, ip, subnet, userAgent string, isTrustedOrigin bool, cancelHash string) (*ent.RecoveryRequest, error) {
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Unknown)"
	}
	client := r.factory.GetClient(ctx, "", "")
	id := idgen.New("req")
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

// GetRecoveryRequestByID loads a recovery request by ID.
//
// Returns nil, nil when no such request exists. The row is returned in whatever
// state it holds, including completed and cancelled, so the caller must check
// status before treating it as an in-flight recovery.
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

// UpdateRecoveryRequestStatus advances a recovery request's state machine.
//
// The write is unconditional and asserts nothing about the current status, so the
// caller must validate the transition; nothing here prevents reviving a cancelled
// request. Errors if requestID does not exist.
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

// GetRecoveryRequestByCancellationHash resolves the hash of a cancellation token
// to its recovery request.
//
// Two contracts differ here from the rest of this file. A missing row is returned
// as ent's *ent.NotFoundError, not as nil, nil, and the error is unwrapped, so
// callers must use ent.IsNotFound. The query filters on the token hash only, with
// no status or expiry predicate, so a request in a terminal state is still
// returned — the caller must check status before acting on the cancellation.
func (r *Repository) GetRecoveryRequestByCancellationHash(ctx context.Context, cancelHash string) (*ent.RecoveryRequest, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.RecoveryRequest.Query().
		Where(recoveryrequest.CancellationTokenHashEQ(cancelHash)).
		Only(ctx)
}

// CreateSecurityBlacklist blocks a recovery origin — IP, subnet, and device
// fingerprint — for a single user until expiresAt. The entry ID is generated here.
//
// The block is scoped to userID, not to the tenant at large, so blacklisting one
// account's attacker does not lock other users off the same address. Expiry is
// stored rather than enforced by deletion: IsOriginBlacklisted filters on it, and
// stale rows simply stop matching.
//
// Returns the raw ent error unwrapped.
func (r *Repository) CreateSecurityBlacklist(ctx context.Context, tenantID, userID, ipAddress, subnet, fpHash, reason string, expiresAt time.Time) (*ent.SecurityBlacklist, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")
	id := idgen.New("blk")
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

// IsOriginBlacklisted reports whether a request origin is currently blocked for a
// user.
//
// The selectors are combined as OR within an AND on user and non-expiry: any one
// of a matching IP, subnet, or fingerprint blocks the request, so an attacker
// must change every signal at once to evade the block. Empty selectors are
// dropped rather than matched, since an empty string would otherwise match rows
// whose column is also empty.
//
// Returns false when the caller supplies no selectors at all — with nothing to
// match on, this reports "not blocked", so callers must not treat a false result
// from an origin-less request as evidence the request was checked.
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

// RevokeUserSessionsExcept revokes a user's active sessions, optionally sparing
// exceptSessionID so a user changing their password is not logged out of the
// device performing the change. An empty exceptSessionID revokes all of them.
//
// Only sessions in active status are considered; a session already in its
// rotation grace window is left untouched. Revocation is applied row by row
// rather than as a single statement, so the operation is not atomic: concurrent
// sign-ins may create sessions that this call never sees.
//
// Returns the number of sessions actually revoked. A per-row failure is skipped
// silently and excluded from the count, so a returned nil error does not by
// itself prove every session was revoked — compare the count against expectation
// before reporting the account as secured.
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

// FlagUserForSecurityReview marks an account as requiring manual review, raised
// on signals such as anomalous recovery attempts.
//
// The flag is set but never cleared here, so clearing it is an explicit operator
// action elsewhere. Errors if the user does not exist; the raw ent error is
// returned unwrapped.
func (r *Repository) FlagUserForSecurityReview(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.UpdateOneID(userID).
		SetSecurityReviewRequired(true).
		Exec(ctx)
}
