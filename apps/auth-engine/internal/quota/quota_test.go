/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/quota/quota_test.go
 * Tier: Unit Tests / Test-Environment Volume Ceilings
 *
 * Drives the hook against a real Ent client with the privacy interceptors
 * installed, because the ceiling is per tenant and per environment only by virtue
 * of those interceptors narrowing the counting query. A test that counted through
 * an unscoped client would pass while the shipped ceiling was global.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package quota

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/enttest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	_ "github.com/mattn/go-sqlite3"
)

const (
	tenantA = "tnt_quota_a"
	tenantB = "tnt_quota_b"
)

// newClient opens an isolated in-memory database with both the privacy
// interceptors and the given ceilings installed, in the order the factory
// installs them.
//
// The database name is derived from the test so two tests never share a
// shared-cache connection, which would let one test's rows count against
// another's ceiling.
func newClient(t *testing.T, limits Limits) *ent.Client {
	t.Helper()

	dsn := fmt.Sprintf("file:quota_%s?mode=memory&cache=shared&_fk=1", t.Name())
	client := enttest.Open(t, "sqlite3", dsn)
	t.Cleanup(func() { client.Close() })

	privacy.AttachPrivacyInterceptors(client)
	AttachHook(client, limits)

	seedTenants(t, client)
	return client
}

// seedTenants installs the two tenants the isolation tests compare, under a
// bypass context because a tenant belongs to no tenant.
func seedTenants(t *testing.T, client *ent.Client) {
	t.Helper()

	ctx := privacy.NewBypassContext(context.Background())
	for _, id := range []string{tenantA, tenantB} {
		if _, err := client.Tenant.Create().
			SetID(id).
			SetName(id).
			SetSlug(id).
			Save(ctx); err != nil {
			t.Fatalf("seeding tenant %s: %v", id, err)
		}
	}
}

// createUsers creates n users in one tenant and environment, returning the error
// from the first create that fails.
func createUsers(client *ent.Client, tenantID, environment, prefix string, n int) error {
	ctx := privacy.NewContext(context.Background(), tenantID, "", environment)
	for i := 0; i < n; i++ {
		_, err := client.User.Create().
			SetID(fmt.Sprintf("usr_%s_%d", prefix, i)).
			SetEmail(fmt.Sprintf("%s%d@example.com", prefix, i)).
			SetEnvironment(user.Environment(environment)).
			Save(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// TestCeilingRefusesTheCreateThatWouldExceedIt is the whole point: the ceiling is
// reached exactly at the configured number, and the next create is refused rather
// than the one after it.
func TestCeilingRefusesTheCreateThatWouldExceedIt(t *testing.T) {
	client := newClient(t, Limits{Users: 3})

	if err := createUsers(client, tenantA, "test", "fill", 3); err != nil {
		t.Fatalf("filling to the ceiling: %v", err)
	}

	err := createUsers(client, tenantA, "test", "over", 1)
	if err == nil {
		t.Fatal("a create past the ceiling was accepted")
	}
	if !errors.Is(err, ErrExceeded) {
		t.Fatalf("refusal does not match ErrExceeded: %v", err)
	}

	var refusal *Exceeded
	if !errors.As(err, &refusal) {
		t.Fatalf("refusal is not an *Exceeded: %v", err)
	}
	if refusal.Resource != "users" || refusal.Limit != 3 {
		t.Errorf("refusal names %d %s, want 3 users", refusal.Limit, refusal.Resource)
	}
	// The message reaches a caller verbatim, so it must not carry a wrapped
	// internal operation name.
	if got := refusal.Error(); got == "" {
		t.Error("refusal renders an empty message")
	}
}

// TestCeilingIsPerTenant checks that one tenant filling its test environment
// leaves every other tenant alone. A ceiling counted globally would let the first
// busy tenant lock out the rest of the deployment.
func TestCeilingIsPerTenant(t *testing.T) {
	client := newClient(t, Limits{Users: 2})

	if err := createUsers(client, tenantA, "test", "a", 2); err != nil {
		t.Fatalf("filling tenant A: %v", err)
	}
	if err := createUsers(client, tenantA, "test", "aover", 1); !errors.Is(err, ErrExceeded) {
		t.Fatalf("tenant A past its ceiling: got %v, want a refusal", err)
	}

	if err := createUsers(client, tenantB, "test", "b", 2); err != nil {
		t.Errorf("tenant B refused while only tenant A was full: %v", err)
	}
}

// TestCeilingIsPerEnvironment checks that a full test environment does not bound
// the live one. The ceiling exists to keep test data small, and applying it to
// live would cap the product at a development limit.
func TestCeilingIsPerEnvironment(t *testing.T) {
	client := newClient(t, Limits{Users: 2})

	if err := createUsers(client, tenantA, "test", "t", 2); err != nil {
		t.Fatalf("filling the test environment: %v", err)
	}

	if err := createUsers(client, tenantA, "live", "l", 5); err != nil {
		t.Errorf("live creates refused under a test ceiling: %v", err)
	}
}

// TestBypassContextIsExempt covers migration, seeding and the retention sweeps,
// none of which is a tenant spending an allowance.
func TestBypassContextIsExempt(t *testing.T) {
	client := newClient(t, Limits{Users: 1})

	ctx := privacy.NewBypassContext(context.Background())
	for i := 0; i < 4; i++ {
		if _, err := client.User.Create().
			SetID(fmt.Sprintf("usr_bypass_%d", i)).
			SetTenantID(tenantA).
			SetEmail(fmt.Sprintf("bypass%d@example.com", i)).
			SetEnvironment("test").
			Save(ctx); err != nil {
			t.Fatalf("bypass create %d refused: %v", i, err)
		}
	}
}

// TestUnscopedContextIsExempt covers the credential lookup that runs before a
// request's environment is known. It carries no scope, so there is no tenant to
// count and nothing to charge.
func TestUnscopedContextIsExempt(t *testing.T) {
	client := newClient(t, Limits{Users: 1})

	if err := createUsers(client, tenantA, "test", "first", 1); err != nil {
		t.Fatalf("first user: %v", err)
	}

	// A context with a tenant but no environment addresses both environments at
	// once, which is not a place a ceiling can be applied.
	ctx := privacy.NewContext(context.Background(), tenantA, "", "")
	if _, err := client.User.Create().
		SetID("usr_unscoped").
		SetEmail("unscoped@example.com").
		SetEnvironment("test").
		Save(ctx); err != nil {
		t.Errorf("create with no environment refused: %v", err)
	}
}

// TestZeroLimitLeavesTheKindUncapped is the reading of an unset field: a ceiling
// nobody configured bounds nothing, rather than refusing everything.
func TestZeroLimitLeavesTheKindUncapped(t *testing.T) {
	client := newClient(t, Limits{Organizations: 1})

	if err := createUsers(client, tenantA, "test", "u", 5); err != nil {
		t.Errorf("users refused under a Limits that only caps organizations: %v", err)
	}
}

// TestUncappedEntitiesPassThrough is the default-allow rule. The privacy
// interceptor next door refuses an entity type it does not recognise; this one
// must not, or it would stop every write the engine makes.
func TestUncappedEntitiesPassThrough(t *testing.T) {
	client := newClient(t, Limits{Users: 1})

	ctx := privacy.NewContext(context.Background(), tenantA, "", "test")
	for i := 0; i < 5; i++ {
		if _, err := client.Role.Create().
			SetID(fmt.Sprintf("rol_%d", i)).
			SetName(fmt.Sprintf("role-%d", i)).
			SetSlug(fmt.Sprintf("role-%d", i)).
			Save(ctx); err != nil {
			t.Fatalf("role %d refused under a user ceiling: %v", i, err)
		}
	}
}

// TestUpdatesAreNotBoundedByTheCeiling separates "hold no more than this" from
// "change nothing more". A tenant sitting at its ceiling must still be able to
// verify an email or ban an account.
func TestUpdatesAreNotBoundedByTheCeiling(t *testing.T) {
	client := newClient(t, Limits{Users: 1})

	if err := createUsers(client, tenantA, "test", "only", 1); err != nil {
		t.Fatalf("first user: %v", err)
	}

	ctx := privacy.NewContext(context.Background(), tenantA, "", "test")
	if err := client.User.UpdateOneID("usr_only_0").
		SetName("Renamed").
		Exec(ctx); err != nil {
		t.Errorf("update refused at the ceiling: %v", err)
	}
}

// TestOrganizationCeilingIsPerEnvironment confirms a tenant's live workspaces do
// not consume the room its test ones have.
//
// This is the property that makes the ceiling usable by a real customer: an
// organization carries an environment of its own, so the count is of one
// environment's workspaces rather than of a set both share. Counted together, a
// tenant running 25 live workspaces would have no room left to rehearse in.
func TestOrganizationCeilingIsPerEnvironment(t *testing.T) {
	client := newClient(t, Limits{Organizations: 2})

	live := privacy.NewContext(context.Background(), tenantA, "", "live")
	for i := 0; i < 2; i++ {
		if _, err := client.Organization.Create().
			SetID(fmt.Sprintf("org_live_%d", i)).
			SetName(fmt.Sprintf("Live Org %d", i)).
			SetSlug(fmt.Sprintf("live-org-%d", i)).
			SetEnvironment(organization.EnvironmentLive).
			Save(live); err != nil {
			t.Fatalf("live organization %d: %v", i, err)
		}
	}

	test := privacy.NewContext(context.Background(), tenantA, "", "test")
	if _, err := client.Organization.Create().
		SetID("org_test_0").
		SetName("Test Org").
		SetSlug("test-org").
		SetEnvironment(organization.EnvironmentTest).
		Save(test); err != nil {
		t.Fatalf("test organization after two live ones: %v", err)
	}

	// The second fills the test ceiling; the third has to be refused, or the
	// per-environment count has become no count at all.
	if _, err := client.Organization.Create().
		SetID("org_test_1").
		SetName("Test Org 2").
		SetSlug("test-org-2").
		SetEnvironment(organization.EnvironmentTest).
		Save(test); err != nil {
		t.Fatalf("second test organization: %v", err)
	}

	_, err := client.Organization.Create().
		SetID("org_test_2").
		SetName("Test Org 3").
		SetSlug("test-org-3").
		SetEnvironment(organization.EnvironmentTest).
		Save(test)
	if !errors.Is(err, ErrExceeded) {
		t.Fatalf("third test organization: got %v, want a refusal", err)
	}
}

// TestOrganizationSlugIsUniquePerEnvironment covers the other half of giving an
// organization an environment: a team rehearses under the slug it means to ship, so
// the same slug has to be available in both.
func TestOrganizationSlugIsUniquePerEnvironment(t *testing.T) {
	client := newClient(t, Limits{})

	for _, env := range []organization.Environment{organization.EnvironmentTest, organization.EnvironmentLive} {
		ctx := privacy.NewContext(context.Background(), tenantA, "", string(env))
		if _, err := client.Organization.Create().
			SetID(fmt.Sprintf("org_%s", env)).
			SetName("Acme").
			SetSlug("acme").
			SetEnvironment(env).
			Save(ctx); err != nil {
			t.Fatalf("organization %q with slug \"acme\": %v", env, err)
		}
	}

	// A second tenant must be able to take the slug too — it identifies a workspace
	// within one tenant's environment, not across the installation.
	ctxB := privacy.NewContext(context.Background(), tenantB, "", "test")
	if _, err := client.Organization.Create().
		SetID("org_other_tenant").
		SetName("Acme").
		SetSlug("acme").
		SetEnvironment(organization.EnvironmentTest).
		Save(ctxB); err != nil {
		t.Fatalf("second tenant with slug \"acme\": %v", err)
	}

	// Within one tenant and environment it is still unique.
	ctxA := privacy.NewContext(context.Background(), tenantA, "", "test")
	_, err := client.Organization.Create().
		SetID("org_dupe").
		SetName("Acme Again").
		SetSlug("acme").
		SetEnvironment(organization.EnvironmentTest).
		Save(ctxA)
	if err == nil {
		t.Fatal("duplicate slug in one tenant and environment: got nil, want a constraint error")
	}
}

// TestAPIKeyCeiling covers the third capped kind, which counts through its
// application rather than a tenant column of its own.
func TestAPIKeyCeiling(t *testing.T) {
	client := newClient(t, Limits{APIKeys: 2})

	sysCtx := privacy.NewBypassContext(context.Background())
	if _, err := client.Application.Create().
		SetID("app_quota").
		SetTenantID(tenantA).
		SetName("Quota App").
		SetEnvironment("test").
		Save(sysCtx); err != nil {
		t.Fatalf("seeding application: %v", err)
	}

	ctx := privacy.NewContext(context.Background(), tenantA, "app_quota", "test")
	for i := 0; i < 2; i++ {
		if _, err := client.ApiKey.Create().
			SetID(fmt.Sprintf("key_%d", i)).
			SetApplicationID("app_quota").
			SetType("publishable").
			SetKeyPrefix("pk_test_").
			SetKeyHash(fmt.Sprintf("hash_%d", i)).
			SetEnvironment("test").
			Save(ctx); err != nil {
			t.Fatalf("api key %d: %v", i, err)
		}
	}

	_, err := client.ApiKey.Create().
		SetID("key_over").
		SetApplicationID("app_quota").
		SetType("publishable").
		SetKeyPrefix("pk_test_").
		SetKeyHash("hash_over").
		SetEnvironment("test").
		Save(ctx)

	var refusal *Exceeded
	if !errors.As(err, &refusal) {
		t.Fatalf("third api key: got %v, want a refusal", err)
	}
	if refusal.Resource != "API keys" {
		t.Errorf("refusal names %q, want \"API keys\"", refusal.Resource)
	}
}

// TestBoundedReportsWhetherAnythingIsCapped is what decides whether the hook is
// installed at all, so an unconfigured deployment pays nothing for it.
func TestBoundedReportsWhetherAnythingIsCapped(t *testing.T) {
	cases := []struct {
		name   string
		limits Limits
		want   bool
	}{
		{"empty", Limits{}, false},
		{"negative", Limits{Users: -1}, false},
		{"users only", Limits{Users: 1}, true},
		{"organizations only", Limits{Organizations: 1}, true},
		{"api keys only", Limits{APIKeys: 1}, true},
		{"session ttl only", Limits{SessionTTL: time.Hour}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.limits.Bounded(); got != tc.want {
				t.Errorf("Bounded() = %v, want %v", got, tc.want)
			}
		})
	}
}

// createSession opens a session row with the given expiry, returning what the
// database actually stored.
//
// The row is created through a scoped context so the hook sees the environment.
// Its user is seeded under a bypass first, because the account is fixture here and
// counting it against the tenant's user ceiling would make these tests fail for a
// reason that has nothing to do with session lifetime.
func createSession(t *testing.T, client *ent.Client, environment, id string, expiresAt time.Time) *ent.Session {
	t.Helper()

	userID := "usr_" + id
	if _, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantA).
		SetEmail(userID + "@example.com").
		SetEnvironment(user.Environment(environment)).
		Save(privacy.NewBypassContext(context.Background())); err != nil {
		t.Fatalf("seeding the session's user: %v", err)
	}

	ctx := privacy.NewContext(context.Background(), tenantA, "", environment)
	sess, err := client.Session.Create().
		SetID(id).
		SetUserID(userID).
		SetRefreshTokenHash("hash_" + id).
		SetExpiresAt(expiresAt).
		Save(ctx)
	if err != nil {
		t.Fatalf("creating session %s: %v", id, err)
	}
	return sess
}

// TestSessionExpiryIsClampedInTest is the floor under the services. Every sign-in
// path resolves its own lifetime, so this is what catches the next one written
// without the ceiling in mind — a session row is what makes a refresh token work,
// and one written past the ceiling is a live test credential nothing else notices.
func TestSessionExpiryIsClampedInTest(t *testing.T) {
	client := newClient(t, Limits{SessionTTL: time.Hour})

	// A week, as the passkey login asks for.
	requested := time.Now().UTC().Add(7 * 24 * time.Hour)
	sess := createSession(t, client, "test", "ses_clamped", requested)

	ceiling := time.Now().UTC().Add(time.Hour)
	if sess.ExpiresAt.After(ceiling.Add(time.Minute)) {
		t.Errorf("session expires at %s, past the %s ceiling", sess.ExpiresAt, ceiling)
	}
	if sess.ExpiresAt.Before(time.Now().UTC()) {
		t.Errorf("session expires at %s, already in the past", sess.ExpiresAt)
	}
}

// TestSessionExpiryUnderTheCeilingIsUntouched keeps the clamp from becoming a
// setting: a short session stays short rather than being extended to the ceiling.
func TestSessionExpiryUnderTheCeilingIsUntouched(t *testing.T) {
	client := newClient(t, Limits{SessionTTL: 24 * time.Hour})

	requested := time.Now().UTC().Add(5 * time.Minute)
	sess := createSession(t, client, "test", "ses_short", requested)

	if !sess.ExpiresAt.Round(time.Second).Equal(requested.Round(time.Second)) {
		t.Errorf("session expires at %s, want the requested %s", sess.ExpiresAt, requested)
	}
}

// TestSessionExpiryIsNotClampedInLive is the other half of the ceiling: a
// customer's month-long session is not a test artifact.
func TestSessionExpiryIsNotClampedInLive(t *testing.T) {
	client := newClient(t, Limits{SessionTTL: time.Hour})

	requested := time.Now().UTC().Add(30 * 24 * time.Hour)
	sess := createSession(t, client, "live", "ses_live", requested)

	if !sess.ExpiresAt.Round(time.Second).Equal(requested.Round(time.Second)) {
		t.Errorf("a live session expires at %s, want the requested %s", sess.ExpiresAt, requested)
	}
}

// TestZeroSessionTTLLeavesExpiryAlone matches the counts: an unset ceiling bounds
// nothing, rather than reading zero as "expire now" and killing every sign-in on
// an unconfigured deployment.
func TestZeroSessionTTLLeavesExpiryAlone(t *testing.T) {
	client := newClient(t, Limits{Users: 1})

	requested := time.Now().UTC().Add(30 * 24 * time.Hour)
	sess := createSession(t, client, "test", "ses_unbounded", requested)

	if !sess.ExpiresAt.Round(time.Second).Equal(requested.Round(time.Second)) {
		t.Errorf("session expires at %s, want the requested %s", sess.ExpiresAt, requested)
	}
}
