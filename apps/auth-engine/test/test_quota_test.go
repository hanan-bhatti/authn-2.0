//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/test_quota_test.go
 * Tier: Integration Tests / Test-Environment Volume Ceilings
 *
 * Drives the ceilings through real endpoints rather than through the ORM, because
 * two things about them are only true at the HTTP boundary. The hook has to be
 * installed on the client the handlers actually reach, and its refusal has to
 * arrive as a 403 a caller can act on rather than the 500 an unmapped error
 * becomes — a ceiling that answered "internal error" would read as a broken
 * engine every time a developer filled their test environment.
 *
 * Each suite boots its own engine with its own ceilings, and the ceilings are
 * small: what matters is the boundary between the last create that fits and the
 * first that does not, and a realistic number would only make that boundary
 * expensive to reach.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	entapikey "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/apikey"
	entapplication "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	entorganization "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	entuser "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/quota"
)

// codeTestQuotaExceeded is the wire code for a create refused for want of room in
// the test environment. It is deliberately not rate_limited: waiting does not
// help, because the ceiling is on stored rows.
const codeTestQuotaExceeded = "test_quota_exceeded"

// seededTestKeys is how many test-environment API keys provisioning installs with
// the harness's application — the publishable key and the secret one.
//
// A ceiling counts what the tenant holds, not what it created through the API, so
// a test that ignored these would be asserting against the wrong number.
const seededTestKeys = 2

// testUserCount returns how many users the tenant holds in the test environment,
// read outside the request path so it reports what was stored rather than what a
// response said was stored.
func (e *testEnv) testUserCount(t *testing.T) int {
	t.Helper()

	ctx := e.bypassContext()
	n, err := e.client(ctx).User.Query().
		Where(entuser.TenantID(testTenant), entuser.EnvironmentEQ(entuser.EnvironmentTest)).
		Count(ctx)
	if err != nil {
		t.Fatalf("counting test users: %v", err)
	}
	return n
}

// testAPIKeyCount returns how many test-environment API keys the tenant holds.
func (e *testEnv) testAPIKeyCount(t *testing.T) int {
	t.Helper()

	ctx := e.bypassContext()
	n, err := e.client(ctx).ApiKey.Query().
		Where(
			entapikey.HasApplicationWith(entapplication.TenantID(testTenant)),
			entapikey.EnvironmentEQ(entapikey.EnvironmentTest),
		).
		Count(ctx)
	if err != nil {
		t.Fatalf("counting test API keys: %v", err)
	}
	return n
}

// testOrganizationCount returns how many workspaces the tenant holds in the test
// environment, which is the set a ceiling on organizations bounds.
func (e *testEnv) testOrganizationCount(t *testing.T) int {
	t.Helper()

	ctx := e.bypassContext()
	n, err := e.client(ctx).Organization.Query().
		Where(
			entorganization.TenantID(testTenant),
			entorganization.EnvironmentEQ(entorganization.EnvironmentTest),
		).
		Count(ctx)
	if err != nil {
		t.Fatalf("counting test organizations: %v", err)
	}
	return n
}

// organizationCount returns how many workspaces the tenant holds in both
// environments together, read under a bypass so the two are visible at once. It is
// what shows a live create landed somewhere rather than nowhere.
func (e *testEnv) organizationCount(t *testing.T) int {
	t.Helper()

	ctx := e.bypassContext()
	n, err := e.client(ctx).Organization.Query().
		Where(entorganization.TenantID(testTenant)).
		Count(ctx)
	if err != nil {
		t.Fatalf("counting organizations: %v", err)
	}
	return n
}

// createOrganization creates an organization on the tenant-admin tier with the
// credential the decorator presents, which is what selects the environment the
// request acts in.
func (e *testEnv) createOrganization(t *testing.T, slug string, decorate ...func(*http.Request)) response {
	t.Helper()

	return e.do(t, http.MethodPost, "/v1/tenant/organizations", map[string]string{
		"name": "Ceiling " + slug,
		"slug": slug,
	}, append([]func(*http.Request){withHeader("X-Authn-Secret-Key", secretKey)}, decorate...)...)
}

// createAPIKey issues a publishable key for the seeded application.
func (e *testEnv) createAPIKey(t *testing.T, name string) response {
	t.Helper()

	return e.admin(t, http.MethodPost, "/v1/admin/keys", map[string]string{
		"name": name,
		"type": "publishable",
	})
}

// assertCarriesNoInternalDetail fails the test when a refusal repeats the wrapping
// the repositories add on the way up.
//
// The ceiling is raised beneath the query builder, so by the time a handler sees
// it the message reads "failed creating user: ...". The response is rebuilt from
// the refusal rather than cut back out of that string, and this is what keeps the
// two from drifting: an internal operation name in a 403 body names a table and a
// call path to anybody who fills their test environment.
func assertCarriesNoInternalDetail(t *testing.T, label string, resp response) {
	t.Helper()

	body := strings.ToLower(string(resp.body))
	for _, leak := range []string{"failed creating", "failed to create", "ent:", "sql:"} {
		if strings.Contains(body, leak) {
			t.Errorf("%s: refusal carries internal detail %q; body %s", label, leak, resp.body)
		}
	}
}

// TestSignupIsRefusedPastTheUserCeiling is the ceiling a tenant meets first, on
// the path anything unattended would use to fill a test environment.
func TestSignupIsRefusedPastTheUserCeiling(t *testing.T) {
	env := newTestEnv(t, nil, nil, withTestLimits(quota.Limits{Users: 2}))

	for i := 0; i < 2; i++ {
		address := fmt.Sprintf("ceiling%d@example.com", i)
		resp := env.signUp(t, address, adminPassword, "Ceiling User")
		assertStatus(t, "signup within the ceiling", resp, http.StatusCreated)
	}

	resp := env.signUp(t, "overflow@example.com", adminPassword, "Overflow User")
	assertRefusedWith(t, "signup past the ceiling", resp, http.StatusForbidden, codeTestQuotaExceeded)
	assertCarriesNoInternalDetail(t, "signup past the ceiling", resp)

	// The refusal has to be a refusal to write, not a status code in front of a
	// write that happened anyway.
	if got := env.testUserCount(t); got != 2 {
		t.Errorf("tenant holds %d test users after a refused signup, want 2", got)
	}

	// A full test environment must not lock out the accounts already in it. The
	// ceiling bounds what may be created, and signing in creates no user.
	t.Run("an existing account still signs in", func(t *testing.T) {
		resp := env.login(t, "ceiling0@example.com", adminPassword)
		assertStatus(t, "login at the ceiling", resp, http.StatusOK)
	})
}

// TestNoCeilingIsInForceByDefault is the guard on the option itself. Every other
// suite in this package boots without ceilings and signs up as many accounts as it
// needs, so a Limits nobody configured has to install no hook at all.
func TestNoCeilingIsInForceByDefault(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	for i := 0; i < 3; i++ {
		address := fmt.Sprintf("unbounded%d@example.com", i)
		resp := env.signUp(t, address, adminPassword, "Unbounded User")
		assertStatus(t, "signup with no ceiling configured", resp, http.StatusCreated)
	}
}

// TestOrganizationCeilingBoundsTestWorkspacesOnly covers both halves of what
// Limits.Organizations bounds. A test credential is refused at the ceiling, and a
// live one is neither refused nor counted against it — so a tenant's production
// workspaces never consume the room it has to rehearse in, which is the failure that
// would otherwise hit the customers with the most reason to use a test environment.
func TestOrganizationCeilingBoundsTestWorkspacesOnly(t *testing.T) {
	env := newTestEnv(t, nil, nil, withTestLimits(quota.Limits{Organizations: 1}))

	resp := env.createOrganization(t, "org-within")
	assertStatus(t, "organization within the ceiling", resp, http.StatusCreated)

	resp = env.createOrganization(t, "org-over")
	assertRefusedWith(t, "organization past the ceiling", resp, http.StatusForbidden, codeTestQuotaExceeded)
	assertCarriesNoInternalDetail(t, "organization past the ceiling", resp)

	if got := env.testOrganizationCount(t); got != 1 {
		t.Errorf("tenant holds %d test organizations after a refused create, want 1", got)
	}

	// A live credential, in a tenant whose test ceiling is already full: allowed,
	// and it does not tighten the test ceiling any further.
	t.Run("a live credential has its own room", func(t *testing.T) {
		resp := env.createOrganization(t, "org-live", withLiveSecretKey())
		assertStatus(t, "organization created with a live key", resp, http.StatusCreated)

		if got := env.organizationCount(t); got != 2 {
			t.Errorf("tenant holds %d organizations in total after a live create, want 2", got)
		}
		if got := env.testOrganizationCount(t); got != 1 {
			t.Errorf("a live create moved the test count to %d, want 1", got)
		}
	})
}

// TestAPIKeyCeilingCountsTheKeysAlreadyIssued bounds the credentials a test
// environment can accumulate, counting the pair provisioning installs with an
// application rather than only the ones issued through the API.
func TestAPIKeyCeilingCountsTheKeysAlreadyIssued(t *testing.T) {
	env := newTestEnv(t, nil, nil, withTestLimits(quota.Limits{APIKeys: seededTestKeys + 1}))

	if got := env.testAPIKeyCount(t); got != seededTestKeys {
		t.Fatalf("the harness seeded %d test keys, want %d; the ceiling below is set against that number",
			got, seededTestKeys)
	}

	resp := env.createAPIKey(t, "Within The Ceiling")
	assertStatus(t, "key within the ceiling", resp, http.StatusCreated)

	resp = env.createAPIKey(t, "Past The Ceiling")
	assertRefusedWith(t, "key past the ceiling", resp, http.StatusForbidden, codeTestQuotaExceeded)
	assertCarriesNoInternalDetail(t, "key past the ceiling", resp)

	if got := env.testAPIKeyCount(t); got != seededTestKeys+1 {
		t.Errorf("tenant holds %d test keys after a refused issuance, want %d", got, seededTestKeys+1)
	}

	// The live environment has its own set, and the test ceiling says nothing about
	// it: a tenant that has filled its test keys still rotates its production ones.
	t.Run("a live credential issues its own keys", func(t *testing.T) {
		resp := env.do(t, http.MethodPost, "/v1/admin/keys", map[string]string{
			"name": "Live Key",
			"type": "publishable",
		}, withLiveSecretKey())
		assertStatus(t, "key issued with a live credential", resp, http.StatusCreated)
	})
}

// TestCeilingsDoNotBoundOneAnother checks that the three ceilings are independent.
// A tenant out of test users still creates organizations, because the kinds are
// counted separately and a create is refused only by its own ceiling.
func TestCeilingsDoNotBoundOneAnother(t *testing.T) {
	env := newTestEnv(t, nil, nil, withTestLimits(quota.Limits{Users: 1, Organizations: 5}))

	resp := env.signUp(t, "only@example.com", adminPassword, "Only User")
	assertStatus(t, "the one permitted signup", resp, http.StatusCreated)

	resp = env.signUp(t, "second@example.com", adminPassword, "Second User")
	assertRefusedWith(t, "the second signup", resp, http.StatusForbidden, codeTestQuotaExceeded)

	resp = env.createOrganization(t, "org-under-a-different-ceiling")
	assertStatus(t, "organization under its own ceiling", resp, http.StatusCreated)
}
