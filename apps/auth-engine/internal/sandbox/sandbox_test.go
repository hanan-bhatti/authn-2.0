package sandbox

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sandboxmessage"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

const (
	tenantA = "tnt_sandboxA"
	tenantB = "tnt_sandboxB"
)

// newTestStore returns a store over an in-memory database with two seeded
// tenants, along with the client for assertions the store does not expose.
//
// The factory is used rather than a bare Ent client so the privacy interceptors
// are installed, which is most of what these tests are checking: the store's own
// predicates and the interceptor's have to agree.
func newTestStore(t *testing.T) (*Store, *ent.Client) {
	t.Helper()

	dsn := fmt.Sprintf("file:sandbox_%s?mode=memory&cache=shared&_fk=1", t.Name())
	factory, err := clientfactory.NewClientFactory("sqlite3", dsn)
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(func() { _ = factory.Close() })

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	for _, id := range []string{tenantA, tenantB} {
		_, err := client.Tenant.Create().
			SetID(id).
			SetName(id).
			SetSlug(id).
			Save(sysCtx)
		if err != nil {
			t.Fatalf("seeding tenant %s: %v", id, err)
		}
	}

	return NewStore(factory), client
}

// testCtx returns a request-like context scoped to a tenant and environment.
func testCtx(tenantID, environment string) context.Context {
	return privacy.NewContext(context.Background(), tenantID, "", environment)
}

// seed writes a capture directly, with an explicit timestamp, so ordering and
// paging can be asserted without depending on how finely the clock is stored.
func seed(t *testing.T, client *ent.Client, tenantID, environment, recipient string, channel sandboxmessage.Channel, createdAt time.Time) string {
	t.Helper()

	sysCtx := privacy.NewBypassContext(context.Background())
	id := fmt.Sprintf("sbxmsg_%s_%d", recipient, createdAt.UnixNano())

	_, err := client.SandboxMessage.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetEnvironment(sandboxmessage.Environment(environment)).
		SetChannel(channel).
		SetRecipient(recipient).
		SetBody("body").
		SetCreatedAt(createdAt).
		Save(sysCtx)
	if err != nil {
		t.Fatalf("seeding captured message: %v", err)
	}

	return id
}

// TestCaptureRequiresScope confirms the store refuses rather than defaulting when
// the context carries no environment to attribute the row to.
func TestCaptureRequiresScope(t *testing.T) {
	store, _ := newTestStore(t)

	message := Message{
		Channel:   sandboxmessage.ChannelEmail,
		Recipient: "ada@example.test",
		Body:      "body",
	}

	cases := []struct {
		name string
		ctx  context.Context
	}{
		{name: "no privacy context", ctx: context.Background()},
		{name: "bypass carries neither tenant nor environment", ctx: privacy.NewBypassContext(context.Background())},
		{name: "tenant without environment", ctx: testCtx(tenantA, "")},
		{name: "environment without tenant", ctx: testCtx("", "test")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Capture(tc.ctx, message); !errors.Is(err, ErrNoScope) {
				t.Fatalf("Capture error = %v, want ErrNoScope", err)
			}
		})
	}
}

// TestCaptureStampsScope confirms the row records the environment the sender was
// acting in rather than the column default.
//
// The interceptor stamps the tenant onto a new row but not the environment, so
// this is the assertion that catches the store dropping its explicit set and
// silently labelling every capture "test".
func TestCaptureStampsScope(t *testing.T) {
	store, _ := newTestStore(t)

	saved, err := store.Capture(testCtx(tenantA, "test"), Message{
		Channel:   sandboxmessage.ChannelEmail,
		Recipient: "ada@example.test",
		Subject:   email.SubjectTwoFactorCode,
		Body:      "<p>code 123456</p>",
		Template:  "two_factor_code",
		Code:      "123456",
		Metadata:  map[string]interface{}{"link": "https://app.test/verify?token=abc"},
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	if saved.TenantID != tenantA {
		t.Errorf("tenant_id = %q, want %q", saved.TenantID, tenantA)
	}
	if saved.Environment != sandboxmessage.EnvironmentTest {
		t.Errorf("environment = %q, want test", saved.Environment)
	}
	if saved.Code != "123456" {
		t.Errorf("code = %q, want 123456", saved.Code)
	}
	if saved.Metadata["link"] != "https://app.test/verify?token=abc" {
		t.Errorf("metadata link = %v, want the captured link", saved.Metadata["link"])
	}
}

// TestListOrdersNewestFirstAndPages confirms the page a harness reads starts at
// the most recent capture, and that the total counts past the page.
func TestListOrdersNewestFirstAndPages(t *testing.T) {
	store, client := newTestStore(t)

	base := time.Now().Add(-time.Hour)
	oldest := seed(t, client, tenantA, "test", "oldest@example.test", sandboxmessage.ChannelEmail, base)
	middle := seed(t, client, tenantA, "test", "middle@example.test", sandboxmessage.ChannelEmail, base.Add(time.Minute))
	newest := seed(t, client, tenantA, "test", "newest@example.test", sandboxmessage.ChannelEmail, base.Add(2*time.Minute))

	ctx := testCtx(tenantA, "test")

	messages, total, err := store.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	got := []string{messages[0].ID, messages[1].ID, messages[2].ID}
	want := []string{newest, middle, oldest}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List order = %v, want %v", got, want)
		}
	}

	page, total, err := store.List(ctx, Filter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("List paged: %v", err)
	}
	if total != 3 {
		t.Errorf("paged total = %d, want the unpaged 3", total)
	}
	if len(page) != 1 || page[0].ID != middle {
		t.Errorf("second page = %v, want just %s", page, middle)
	}
}

// TestListClampsLimit confirms an oversized page request is capped rather than
// honoured, since a page of rendered documents is the expensive kind of unbounded.
func TestListClampsLimit(t *testing.T) {
	store, client := newTestStore(t)

	base := time.Now().Add(-time.Hour)
	for i := 0; i < maxListLimit+5; i++ {
		seed(t, client, tenantA, "test", fmt.Sprintf("user%d@example.test", i), sandboxmessage.ChannelEmail, base.Add(time.Duration(i)*time.Second))
	}

	messages, total, err := store.List(testCtx(tenantA, "test"), Filter{Limit: 100000})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != maxListLimit+5 {
		t.Errorf("total = %d, want %d", total, maxListLimit+5)
	}
	if len(messages) != maxListLimit {
		t.Errorf("page length = %d, want the cap of %d", len(messages), maxListLimit)
	}
}

// TestListFilters confirms the channel and recipient filters narrow to what a
// harness polls for.
func TestListFilters(t *testing.T) {
	store, client := newTestStore(t)

	base := time.Now().Add(-time.Hour)
	seed(t, client, tenantA, "test", "ada@example.test", sandboxmessage.ChannelEmail, base)
	seed(t, client, tenantA, "test", "+15550001111", sandboxmessage.ChannelSms, base.Add(time.Minute))
	seed(t, client, tenantA, "test", "grace@example.test", sandboxmessage.ChannelEmail, base.Add(2*time.Minute))

	ctx := testCtx(tenantA, "test")

	_, total, err := store.List(ctx, Filter{Channel: string(sandboxmessage.ChannelSms)})
	if err != nil {
		t.Fatalf("List by channel: %v", err)
	}
	if total != 1 {
		t.Errorf("sms total = %d, want 1", total)
	}

	messages, total, err := store.List(ctx, Filter{Recipient: "ada@example.test"})
	if err != nil {
		t.Fatalf("List by recipient: %v", err)
	}
	if total != 1 || len(messages) != 1 || messages[0].Recipient != "ada@example.test" {
		t.Errorf("recipient filter returned %d of %d, want just ada@example.test", len(messages), total)
	}
}

// TestReadsAreConfinedToTenantAndEnvironment is the isolation assertion: a
// captured code is a usable credential, so another tenant reading one would be a
// straightforward account takeover in a shared test deployment.
func TestReadsAreConfinedToTenantAndEnvironment(t *testing.T) {
	store, client := newTestStore(t)

	base := time.Now().Add(-time.Hour)
	ownID := seed(t, client, tenantA, "test", "ada@example.test", sandboxmessage.ChannelEmail, base)
	seed(t, client, tenantB, "test", "grace@example.test", sandboxmessage.ChannelEmail, base)

	// Another tenant sees nothing of it, by list or by ID.
	_, total, err := store.List(testCtx(tenantB, "test"), Filter{Recipient: "ada@example.test"})
	if err != nil {
		t.Fatalf("List as the other tenant: %v", err)
	}
	if total != 0 {
		t.Errorf("the other tenant counted %d of this tenant's captures, want 0", total)
	}
	if _, err := store.Get(testCtx(tenantB, "test"), ownID); err == nil {
		t.Error("the other tenant read this tenant's captured message by ID")
	}

	// Nor does the owning tenant's live credential, which is what keeps a live key
	// from reaching test-environment codes.
	if _, err := store.Get(testCtx(tenantA, "live"), ownID); err == nil {
		t.Error("a live-environment read reached a test-environment capture")
	}

	if _, err := store.Get(testCtx(tenantA, "test"), ownID); err != nil {
		t.Errorf("the owning tenant could not read its own capture: %v", err)
	}
}

// TestPurgeEmptiesOnlyTheCallersInbox confirms emptying between runs does not
// reach past the caller's own tenant and environment.
func TestPurgeEmptiesOnlyTheCallersInbox(t *testing.T) {
	store, client := newTestStore(t)

	base := time.Now().Add(-time.Hour)
	seed(t, client, tenantA, "test", "ada@example.test", sandboxmessage.ChannelEmail, base)
	seed(t, client, tenantA, "test", "+15550001111", sandboxmessage.ChannelSms, base.Add(time.Minute))
	seed(t, client, tenantB, "test", "grace@example.test", sandboxmessage.ChannelEmail, base)

	removed, err := store.Purge(testCtx(tenantA, "test"))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}

	if _, total, _ := store.List(testCtx(tenantA, "test"), Filter{}); total != 0 {
		t.Errorf("caller's inbox still holds %d messages", total)
	}
	if _, total, _ := store.List(testCtx(tenantB, "test"), Filter{}); total != 1 {
		t.Errorf("the other tenant's inbox was emptied too")
	}

	if _, err := store.Purge(privacy.NewBypassContext(context.Background())); !errors.Is(err, ErrNoScope) {
		t.Errorf("Purge on an unscoped context = %v, want ErrNoScope", err)
	}
}

// TestPurgeExpiredSweepsByAgeAcrossTenants covers the retention task: it runs
// under a bypass so one pass covers every tenant, and it must delete strictly by
// age.
func TestPurgeExpiredSweepsByAgeAcrossTenants(t *testing.T) {
	store, client := newTestStore(t)

	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)

	for i := 0; i < 5; i++ {
		seed(t, client, tenantA, "test", fmt.Sprintf("old%d@example.test", i), sandboxmessage.ChannelEmail, cutoff.Add(-time.Duration(i+1)*time.Hour))
	}
	seed(t, client, tenantB, "test", "oldB@example.test", sandboxmessage.ChannelEmail, cutoff.Add(-time.Hour))
	freshA := seed(t, client, tenantA, "test", "fresh@example.test", sandboxmessage.ChannelEmail, now.Add(-time.Minute))

	sysCtx := privacy.NewBypassContext(context.Background())

	// A batch size below the backlog exercises the loop rather than a single pass.
	removed, err := store.PurgeExpired(sysCtx, cutoff, 2)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if removed != 6 {
		t.Errorf("removed = %d, want the 6 aged rows across both tenants", removed)
	}

	if _, err := store.Get(testCtx(tenantA, "test"), freshA); err != nil {
		t.Errorf("a message newer than the cutoff was swept: %v", err)
	}

	// A second pass over a swept table removes nothing and reports no error, which
	// is what lets the sweeper run every interval regardless of backlog.
	removed, err = store.PurgeExpired(sysCtx, cutoff, 2)
	if err != nil {
		t.Fatalf("PurgeExpired second pass: %v", err)
	}
	if removed != 0 {
		t.Errorf("second pass removed %d rows, want 0", removed)
	}

	if _, err := store.PurgeExpired(sysCtx, cutoff, 0); err == nil {
		t.Error("PurgeExpired accepted a non-positive batch size, which would loop forever")
	}
}
