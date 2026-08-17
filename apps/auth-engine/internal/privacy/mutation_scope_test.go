package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/enttest"
	entuser "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	_ "github.com/mattn/go-sqlite3"
)

const (
	scopeTenantA = "tnt_scope_a"
	scopeTenantB = "tnt_scope_b"
)

// newMutationScopeFixture returns a client holding one user per tenant, plus a
// bypass context for arranging and inspecting rows either tenant owns.
//
// Each test opens its own in-memory database, since the assertions turn on
// whether a write landed and a shared database would let one test observe
// another's writes.
func newMutationScopeFixture(t *testing.T, dsn string) (*ent.Client, context.Context) {
	t.Helper()

	client := enttest.Open(t, "sqlite3", "file:"+dsn+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() { client.Close() })
	AttachPrivacyInterceptors(client)

	sys := NewBypassContext(context.Background())
	for _, id := range []string{scopeTenantA, scopeTenantB} {
		if _, err := client.Tenant.Create().SetID(id).SetName(id).SetSlug(id).Save(sys); err != nil {
			t.Fatalf("seed tenant %s: %v", id, err)
		}
	}

	seed := func(id, tenantID, email string, env entuser.Environment) {
		if _, err := client.User.Create().
			SetID(id).
			SetTenantID(tenantID).
			SetEnvironment(env).
			SetEmail(email).
			SetName("Before").
			Save(sys); err != nil {
			t.Fatalf("seed user %s: %v", id, err)
		}
	}
	seed("usr_a", scopeTenantA, "a@example.test", entuser.EnvironmentTest)
	seed("usr_b", scopeTenantB, "b@example.test", entuser.EnvironmentTest)
	seed("usr_b_live", scopeTenantB, "b-live@example.test", entuser.EnvironmentLive)

	return client, sys
}

// tenantACtx is the scope a legitimately authenticated admin of tenant A holds.
func tenantACtx() context.Context {
	return NewContext(context.Background(), scopeTenantA, "", "test")
}

func statusOf(t *testing.T, client *ent.Client, sys context.Context, userID string) entuser.Status {
	t.Helper()
	row, err := client.User.Get(sys, userID)
	if err != nil {
		t.Fatalf("read back %s: %v", userID, err)
	}
	return row.Status
}

// TestUpdateByIDCannotReachAnotherTenant covers the case a request-supplied row
// identifier creates: the caller is a real admin, but the ID names someone
// else's row.
func TestUpdateByIDCannotReachAnotherTenant(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_update_id")

	err := client.User.UpdateOneID("usr_b").
		SetStatus(entuser.StatusBanned).
		Exec(tenantACtx())
	if err == nil {
		t.Fatal("tenant A updated tenant B's user")
	}
	if !ent.IsNotFound(err) {
		t.Errorf("want a not-found error so handlers render 404, got %T: %v", err, err)
	}

	if got := statusOf(t, client, sys, "usr_b"); got != entuser.StatusActive {
		t.Errorf("tenant B's user status changed to %q", got)
	}
}

// TestUpdateByIDReachesOwnTenant is the other half: the narrowing must not break
// the ordinary case.
func TestUpdateByIDReachesOwnTenant(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_update_own")

	if err := client.User.UpdateOneID("usr_a").
		SetStatus(entuser.StatusBanned).
		Exec(tenantACtx()); err != nil {
		t.Fatalf("tenant A could not update its own user: %v", err)
	}

	if got := statusOf(t, client, sys, "usr_a"); got != entuser.StatusBanned {
		t.Errorf("status = %q, want banned", got)
	}
}

// TestBulkUpdateIsConfinedToOwnTenant checks the predicate form a bulk update
// takes, which carries no ID at all and would otherwise span the table.
func TestBulkUpdateIsConfinedToOwnTenant(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_bulk_update")

	n, err := client.User.Update().
		SetStatus(entuser.StatusSuspended).
		Save(tenantACtx())
	if err != nil {
		t.Fatalf("bulk update: %v", err)
	}
	if n != 1 {
		t.Errorf("rows affected = %d, want 1 (only tenant A's user)", n)
	}

	if got := statusOf(t, client, sys, "usr_b"); got != entuser.StatusActive {
		t.Errorf("tenant B's user was swept into tenant A's bulk update: status %q", got)
	}
}

// TestDeleteCannotReachAnotherTenant covers deletion, where a successful
// cross-tenant write is unrecoverable rather than merely wrong.
func TestDeleteCannotReachAnotherTenant(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_delete")

	err := client.User.DeleteOneID("usr_b").Exec(tenantACtx())
	if err == nil {
		t.Fatal("tenant A deleted tenant B's user")
	}
	if !ent.IsNotFound(err) {
		t.Errorf("want a not-found error, got %T: %v", err, err)
	}

	if _, err := client.User.Get(sys, "usr_b"); err != nil {
		t.Errorf("tenant B's user no longer exists: %v", err)
	}
}

// TestParentScopedEntityIsConfined covers an entity with no tenant_id of its
// own. A session is reachable only through its user, so the filter has to travel
// the join — and a session is exactly what an admin action revokes by user ID.
func TestParentScopedEntityIsConfined(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_session")

	mk := func(id, userID string) {
		if _, err := client.Session.Create().
			SetID(id).
			SetUserID(userID).
			SetRefreshTokenHash("hash_" + id).
			SetExpiresAt(time.Now().Add(time.Hour)).
			Save(sys); err != nil {
			t.Fatalf("seed session %s: %v", id, err)
		}
	}
	mk("ses_a", "usr_a")
	mk("ses_b", "usr_b")

	n, err := client.Session.Update().SetStatus("revoked").Save(tenantACtx())
	if err != nil {
		t.Fatalf("session update: %v", err)
	}
	if n != 1 {
		t.Errorf("rows affected = %d, want 1 (only tenant A's session)", n)
	}

	other, err := client.Session.Get(sys, "ses_b")
	if err != nil {
		t.Fatalf("read back ses_b: %v", err)
	}
	if other.Status == "revoked" {
		t.Error("tenant A revoked tenant B's session")
	}
}

// TestEnvironmentNarrowsMutations checks the second half of the scope. A test
// credential must not reach live rows, which is the same boundary the read path
// applies.
func TestEnvironmentNarrowsMutations(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_environment")

	// Tenant B's own admin, holding a test-environment credential.
	testEnvCtx := NewContext(context.Background(), scopeTenantB, "", "test")

	err := client.User.UpdateOneID("usr_b_live").
		SetStatus(entuser.StatusBanned).
		Exec(testEnvCtx)
	if err == nil {
		t.Fatal("a test-environment credential updated a live row")
	}

	if got := statusOf(t, client, sys, "usr_b_live"); got != entuser.StatusActive {
		t.Errorf("live row status changed to %q", got)
	}
}

// TestUnscopedMutationIsRefused checks the fail-closed direction: a context that
// never passed through authenticating middleware must not write at all.
func TestUnscopedMutationIsRefused(t *testing.T) {
	client, _ := newMutationScopeFixture(t, "scope_unscoped")

	err := client.User.UpdateOneID("usr_a").
		SetStatus(entuser.StatusBanned).
		Exec(context.Background())
	if !errors.Is(err, ErrPrivacyViolation) {
		t.Errorf("want ErrPrivacyViolation, got %v", err)
	}
}

// TestBypassStillSpansTenants keeps the system paths working. Migration, seeding
// and the retention sweep have no tenant by nature.
func TestBypassStillSpansTenants(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_bypass")

	n, err := client.User.Update().SetStatus(entuser.StatusSuspended).Save(sys)
	if err != nil {
		t.Fatalf("bypass bulk update: %v", err)
	}
	if n != 3 {
		t.Errorf("rows affected = %d, want 3 (every seeded user)", n)
	}
}

// TestCreateStampsCallerTenant confirms the create path still supplies the
// tenant, which is the one write shape a filter cannot express.
func TestCreateStampsCallerTenant(t *testing.T) {
	client, sys := newMutationScopeFixture(t, "scope_create_stamp")

	created, err := client.User.Create().
		SetID("usr_new").
		SetEnvironment(entuser.EnvironmentTest).
		SetEmail("new@example.test").
		Save(tenantACtx())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.TenantID != scopeTenantA {
		t.Errorf("tenant_id = %q, want %q", created.TenantID, scopeTenantA)
	}

	if _, err := client.User.Get(sys, "usr_new"); err != nil {
		t.Errorf("read back: %v", err)
	}
}

// TestCreateNamingForeignTenantIsRefused confirms an explicitly named tenant is
// refused rather than rewritten, so a caller trusting an unverified tenant is
// surfaced instead of silently redirected.
func TestCreateNamingForeignTenantIsRefused(t *testing.T) {
	client, _ := newMutationScopeFixture(t, "scope_create_foreign")

	_, err := client.User.Create().
		SetID("usr_foreign").
		SetTenantID(scopeTenantB).
		SetEnvironment(entuser.EnvironmentTest).
		SetEmail("foreign@example.test").
		Save(tenantACtx())
	if !errors.Is(err, ErrPrivacyViolation) {
		t.Errorf("want ErrPrivacyViolation, got %v", err)
	}
}
