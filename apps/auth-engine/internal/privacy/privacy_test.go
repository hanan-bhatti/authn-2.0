package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/enttest"
	_ "github.com/mattn/go-sqlite3"
)

func TestPrivacyInterceptor_AutomaticTenantIsolation(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent_privacy_test?mode=memory&cache=shared&_fk=1")
	defer client.Close()

	// Attach automatic privacy interceptors
	AttachPrivacyInterceptors(client)

	// Step 1: Create background system context (Bypass) to seed Tenant A and Tenant B users
	sysCtx := NewBypassContext(context.Background())

	// Create Tenant A
	tA, err := client.Tenant.Create().
		SetID("tnt_tenantA").
		SetName("Tenant A").
		SetSlug("tenant-a").
		Save(sysCtx)
	if err != nil {
		t.Fatalf("failed creating tenant A: %v", err)
	}

	// Create Tenant B
	tB, err := client.Tenant.Create().
		SetID("tnt_tenantB").
		SetName("Tenant B").
		SetSlug("tenant-b").
		Save(sysCtx)
	if err != nil {
		t.Fatalf("failed creating tenant B: %v", err)
	}

	// Create User A under Tenant A
	_, err = client.User.Create().
		SetID("usr_userA").
		SetTenantID(tA.ID).
		SetEmail("alice@tenant-a.com").
		SetPasswordHash("hashA").
		SetEnvironment("test").
		SetCreatedAt(time.Now()).
		SetUpdatedAt(time.Now()).
		Save(sysCtx)
	if err != nil {
		t.Fatalf("failed creating user A: %v", err)
	}

	// Create User B under Tenant B with SAME email structure
	_, err = client.User.Create().
		SetID("usr_userB").
		SetTenantID(tB.ID).
		SetEmail("bob@tenant-b.com").
		SetPasswordHash("hashB").
		SetEnvironment("test").
		SetCreatedAt(time.Now()).
		SetUpdatedAt(time.Now()).
		Save(sysCtx)
	if err != nil {
		t.Fatalf("failed creating user B: %v", err)
	}

	// Step 2: Query WITHOUT any manual `Where(user.TenantID(...))` clause, relying STRICTLY on PrivacyContext
	ctxA := NewContext(context.Background(), "tnt_tenantA", "", "test")

	// Repository function "forgets" Where() clause completely: client.User.Query().All(ctxA)
	usersA, err := client.User.Query().All(ctxA)
	if err != nil {
		t.Fatalf("unexpected query error for tenant A: %v", err)
	}

	if len(usersA) != 1 {
		t.Fatalf("expected exactly 1 user for tenant A, got %d", len(usersA))
	}
	if usersA[0].ID != "usr_userA" {
		t.Fatalf("expected user 'usr_userA', got '%s'", usersA[0].ID)
	}

	// Step 3: Query scoped to Tenant B — must NEVER return Tenant A's user
	ctxB := NewContext(context.Background(), "tnt_tenantB", "", "test")
	usersB, err := client.User.Query().All(ctxB)
	if err != nil {
		t.Fatalf("unexpected query error for tenant B: %v", err)
	}

	if len(usersB) != 1 {
		t.Fatalf("expected exactly 1 user for tenant B, got %d", len(usersB))
	}
	if usersB[0].ID != "usr_userB" {
		t.Fatalf("expected user 'usr_userB', got '%s'", usersB[0].ID)
	}
}

func TestPrivacyInterceptor_AutomaticEnvironmentIsolation(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent_env_test?mode=memory&cache=shared&_fk=1")
	defer client.Close()

	AttachPrivacyInterceptors(client)
	sysCtx := NewBypassContext(context.Background())

	tnt, err := client.Tenant.Create().
		SetID("tnt_env_demo").
		SetName("Env Demo Tenant").
		SetSlug("env-demo").
		Save(sysCtx)
	if err != nil {
		t.Fatalf("failed creating tenant: %v", err)
	}

	// User in TEST environment
	_, err = client.User.Create().
		SetID("usr_test_mode").
		SetTenantID(tnt.ID).
		SetEmail("dev@example.com").
		SetPasswordHash("hashTest").
		SetEnvironment("test").
		SetCreatedAt(time.Now()).
		SetUpdatedAt(time.Now()).
		Save(sysCtx)
	if err != nil {
		t.Fatalf("failed creating test user: %v", err)
	}

	// User in LIVE environment
	_, err = client.User.Create().
		SetID("usr_live_mode").
		SetTenantID(tnt.ID).
		SetEmail("prod@example.com").
		SetPasswordHash("hashLive").
		SetEnvironment("live").
		SetCreatedAt(time.Now()).
		SetUpdatedAt(time.Now()).
		Save(sysCtx)
	if err != nil {
		t.Fatalf("failed creating live user: %v", err)
	}

	// Query scoped to "test" environment without manual Where(user.Environment("test"))
	ctxTest := NewContext(context.Background(), tnt.ID, "", "test")
	testUsers, err := client.User.Query().All(ctxTest)
	if err != nil {
		t.Fatalf("query error in test environment: %v", err)
	}
	if len(testUsers) != 1 || testUsers[0].ID != "usr_test_mode" {
		t.Fatalf("expected 1 test user 'usr_test_mode', got %v", testUsers)
	}

	// Query scoped to "live" environment without manual Where()
	ctxLive := NewContext(context.Background(), tnt.ID, "", "live")
	liveUsers, err := client.User.Query().All(ctxLive)
	if err != nil {
		t.Fatalf("query error in live environment: %v", err)
	}
	if len(liveUsers) != 1 || liveUsers[0].ID != "usr_live_mode" {
		t.Fatalf("expected 1 live user 'usr_live_mode', got %v", liveUsers)
	}
}

func TestPrivacyInterceptor_FailClosedOnMissingContext(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent_failclosed_test?mode=memory&cache=shared&_fk=1")
	defer client.Close()

	AttachPrivacyInterceptors(client)

	// Attempting a query on multi-tenant User table with bare un-scoped context.Context MUST FAIL CLOSED
	bareCtx := context.Background()
	_, err := client.User.Query().All(bareCtx)
	if err == nil {
		t.Fatalf("expected fail-closed error when querying User with un-scoped context, but query succeeded")
	}
	if !errors.Is(err, ErrPrivacyViolation) {
		t.Fatalf("expected ErrPrivacyViolation error, got: %v", err)
	}

	// Attempting a mutation on multi-tenant User table with bare un-scoped context MUST FAIL CLOSED
	_, err = client.User.Create().
		SetID("usr_unauthorized").
		SetEmail("hacker@example.com").
		SetPasswordHash("hash").
		Save(bareCtx)

	if err == nil {
		t.Fatalf("expected fail-closed error when creating User with un-scoped context, but mutation succeeded")
	}
	if !errors.Is(err, ErrPrivacyViolation) {
		t.Fatalf("expected ErrPrivacyViolation error on mutation, got: %v", err)
	}
}
