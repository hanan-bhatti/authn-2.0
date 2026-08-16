//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/tenant_isolation_test.go
 * Tier: Integration Test
 *
 * Proves that the tenant a request acts on comes from the credential that
 * authenticated it, and never from the request. Each test drives a route with a
 * credential for one tenant while naming a second tenant in the query string or
 * body, then reads both tenants' rows directly to confirm which one moved.
 *
 * Asserting on the stored rows rather than on the response status is deliberate:
 * a handler that answers 200 after writing to the wrong tenant is the exact
 * failure these tests exist to catch, and a status assertion would pass.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
)

// victimTenant is the tenant a request names but holds no credential for.
const victimTenant = "tnt_00000000000000000000000000000099"

// stubAdminGuard stands in for the real admin middleware, resolving tenantID the
// way a verified sk_ key would.
//
// It installs both the request local and the privacy context, because those are
// two independent halves of tenant scoping: the local is what handlers read, and
// the context is what the Ent interceptor filters on. A guard that set only one
// would let a test pass against a handler that is broken in production.
func stubAdminGuard(tenantID string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.SetUserContext(privacy.NewContext(c.UserContext(), tenantID, "", testEnvironment))
		c.Locals("tenant_id", tenantID)
		c.Locals("environment", testEnvironment)
		return c.Next()
	}
}

// seedVictimTenant creates the second tenant whose rows must stay untouched.
func (e *testEnv) seedVictimTenant(t *testing.T) {
	t.Helper()
	if err := e.authRepo.EnsureTenantExists(e.bypassContext(), victimTenant); err != nil {
		t.Fatalf("seeding victim tenant: %v", err)
	}
}

// TestPasswordPolicyRouteIgnoresQueryTenant drives PUT
// /v1/tenant/password-policy with a credential for the test tenant while naming
// the victim tenant in the query string.
func TestPasswordPolicyRouteIgnoresQueryTenant(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	policy.NewHandler(env.policyRepo).RegisterRoutes(app, stubAdminGuard(testTenant))

	// A length no default uses, so a match cannot be a coincidence.
	const plantedLength = 23
	req, err := newJSONRequest(http.MethodPut,
		"/v1/tenant/password-policy?tenant_id="+victimTenant,
		map[string]any{"min_length": plantedLength})
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := app.Test(req, requestTimeoutMillis)
	if err != nil {
		t.Fatalf("driving password-policy update: %v", err)
	}
	resp.Body.Close()

	ctx := env.bypassContext()
	victimPolicy, err := env.policyRepo.GetPasswordPolicy(ctx, victimTenant)
	if err != nil {
		t.Fatalf("reading victim policy: %v", err)
	}
	if victimPolicy.MinLength == plantedLength {
		t.Fatalf("query-supplied tenant_id reached tenant %s: min_length is %d",
			victimTenant, plantedLength)
	}

	ownPolicy, err := env.policyRepo.GetPasswordPolicy(ctx, testTenant)
	if err != nil {
		t.Fatalf("reading own policy: %v", err)
	}
	if ownPolicy.MinLength != plantedLength {
		t.Fatalf("write did not land in the authenticated tenant: min_length is %d, want %d",
			ownPolicy.MinLength, plantedLength)
	}
}

// TestCreateRoleIgnoresBodyTenant drives POST /v1/tenant/roles with a credential
// for the test tenant while naming the victim tenant in the body.
//
// This route is the whole cross-tenant RBAC takeover in one call: a role created
// inside another tenant carries whatever permissions the body asked for.
func TestCreateRoleIgnoresBodyTenant(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)

	rbacService := rbac.NewService(
		rbac.NewRepository(env.factory),
		rbac.NewAuditLogger(env.factory),
		env.cfg,
	)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	rbac.NewHandler(rbacService).RegisterRoutes(app, stubAdminGuard(testTenant), nil, nil)

	const plantedSlug = "planted-cross-tenant-role"
	req, err := newJSONRequest(http.MethodPost, "/v1/tenant/roles", map[string]any{
		"tenant_id":   victimTenant,
		"name":        "Planted Role",
		"slug":        plantedSlug,
		"permissions": []string{"users:manage"},
	})
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := app.Test(req, requestTimeoutMillis)
	if err != nil {
		t.Fatalf("driving role creation: %v", err)
	}
	resp.Body.Close()

	ctx := env.bypassContext()
	victimRoles, err := rbacService.ListRoles(privacy.NewContext(ctx, victimTenant, "", testEnvironment), victimTenant)
	if err != nil {
		t.Fatalf("listing victim roles: %v", err)
	}
	for _, r := range victimRoles {
		if r.Slug == plantedSlug {
			t.Fatalf("body-supplied tenant_id created role %q inside tenant %s", plantedSlug, victimTenant)
		}
	}

	ownRoles, err := rbacService.ListRoles(privacy.NewContext(ctx, testTenant, "", testEnvironment), testTenant)
	if err != nil {
		t.Fatalf("listing own roles: %v", err)
	}
	var found bool
	for _, r := range ownRoles {
		if r.Slug == plantedSlug {
			found = true
		}
	}
	if !found {
		t.Fatalf("role was not created in the authenticated tenant %s", testTenant)
	}
}

// TestRecoveryInitiateIgnoresBodyTenant drives POST
// /v1/client/auth/recovery/initiate with the publishable key for the test tenant
// while naming the victim tenant and one of its users in the body.
//
// The service looks the account up under a bypass context, so the tenant it is
// handed is the only thing separating one customer's accounts from another's. A
// match here means recovery started against an account the caller does not own.
func TestRecoveryInitiateIgnoresBodyTenant(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)

	const victimEmail = "owner@victim-tenant.example"
	ctx := env.bypassContext()
	victimUser, err := env.authRepo.CreateUser(ctx, "usr_victim_recovery_target",
		victimTenant, testEnvironment, victimEmail, "argon2id$placeholder$hash", "Victim Owner")
	if err != nil {
		t.Fatalf("seeding victim user: %v", err)
	}

	// The victim needs one usable proof method, because the service refuses an
	// account that has none before it ever writes a request row. Email OTP is
	// enabled by default and asks only for a verified address, so verifying the
	// address is what makes a successful cross-tenant reach leave the evidence
	// this test asserts on.
	if _, err := env.factory.GetClient(ctx, victimTenant, testEnvironment).
		User.UpdateOneID(victimUser.ID).SetEmailVerified(true).Save(ctx); err != nil {
		t.Fatalf("marking victim email verified: %v", err)
	}

	resp := env.do(t, http.MethodPost, "/v1/client/auth/recovery/initiate", map[string]any{
		"tenant_id":   victimTenant,
		"environment": testEnvironment,
		"email":       victimEmail,
	})

	// The endpoint answers in the shape of a hit either way, so the reply proves
	// nothing. Whether a recovery request row exists for the victim does.
	requests, err := env.factory.GetClient(ctx, victimTenant, testEnvironment).
		RecoveryRequest.Query().All(ctx)
	if err != nil {
		t.Fatalf("querying recovery requests: %v", err)
	}
	for _, r := range requests {
		if r.UserID == victimUser.ID {
			t.Fatalf("body-supplied tenant_id started recovery for user %s in tenant %s (status %d)",
				victimUser.ID, victimTenant, resp.status)
		}
	}
}

// TestSessionPolicyDrivesRefreshCookieLifetime proves the settings resolver reaches
// cookie construction: a tenant's stored refresh lifetime, not the deployment
// default, decides how long the refresh cookie lives.
//
// The writer expresses lifetime as an absolute Expires rather than Max-Age, so the
// assertion measures the remaining window and allows a tolerance for the time the
// request itself takes.
func TestSessionPolicyDrivesRefreshCookieLifetime(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	// refreshLifetime returns how long the refresh cookie on resp is good for.
	refreshLifetime := func(t *testing.T, resp response, when time.Time) time.Duration {
		t.Helper()
		cookie := resp.cookie(refreshCookieName)
		if cookie == nil {
			t.Fatal("signup set no refresh cookie")
		}
		if cookie.Expires.IsZero() {
			t.Fatal("refresh cookie carries no expiry, so it is a session cookie")
		}
		return cookie.Expires.Sub(when)
	}

	// tolerance absorbs the wall-clock cost of the signup request; the two
	// lifetimes under test differ by 27 days, so it cannot mask a wrong answer.
	const tolerance = 2 * time.Minute

	before := time.Now()
	resp := env.signUp(t, "default-ttl@example.com", "UserPassword123!", "Default TTL")
	if resp.status != http.StatusCreated && resp.status != http.StatusOK {
		t.Fatalf("signup before policy change: status %d body %s", resp.status, resp.body)
	}
	got := refreshLifetime(t, resp, before)
	if diff := got - env.cfg.RefreshTokenTTL; diff > tolerance || diff < -tolerance {
		t.Fatalf("with no stored policy the refresh cookie lives %v, want the deployment default %v",
			got, env.cfg.RefreshTokenTTL)
	}

	// Three days is inside the accepted 1-365 range and unlike the 30-day
	// deployment default, so the assertion cannot pass on a fallback.
	const storedDays = 3
	if _, err := env.policyRepo.UpdateSessionPolicy(env.bypassContext(), testTenant,
		policy.SessionPolicy{RefreshTokenTTLDays: storedDays}); err != nil {
		t.Fatalf("storing session policy: %v", err)
	}

	want := time.Duration(storedDays) * 24 * time.Hour
	before = time.Now()
	resp = env.signUp(t, "custom-ttl@example.com", "UserPassword123!", "Custom TTL")
	if resp.status != http.StatusCreated && resp.status != http.StatusOK {
		t.Fatalf("signup after policy change: status %d body %s", resp.status, resp.body)
	}
	got = refreshLifetime(t, resp, before)
	if diff := got - want; diff > tolerance || diff < -tolerance {
		t.Fatalf("refresh cookie lives %v, want %v from the tenant's stored refresh_token_ttl_days",
			got, want)
	}
}

// newJSONRequest builds a JSON request for an app mounted inside a single test,
// rather than the shared harness app that testEnv.do drives. The routes below sit
// behind a stub admin guard, so no publishable key is attached.
func newJSONRequest(method, path string, payload any) (*http.Request, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}
