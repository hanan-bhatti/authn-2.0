/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/purge_test.go
 * Tier: Persistence Layer / Session Store / Tests
 *
 * Description: Covers the retention sweep over session rows. The properties
 *              that matter are what it refuses to delete — anything that can
 *              still authenticate, and anything still inside the window where a
 *              replayed refresh token is recognised as theft — and that it
 *              clears a backlog larger than one batch.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

const (
	purgeTestTenant = "tnt_purge"
	purgeTestUser   = "usr_purge"
)

// setupPurgeTest returns a repository over an empty schema, a bypass context and
// the raw client for arranging rows the repository has no method to create.
func setupPurgeTest(t *testing.T) (*Repository, context.Context, *ent.Client) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "session_purge_test_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	dbPath := filepath.Join(tmpDir, "test.db") + "?_fk=1"
	factory, err := clientfactory.NewClientFactory("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("client factory: %v", err)
	}
	t.Cleanup(func() { factory.Close() })

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, purgeTestTenant, "test")
	if err := client.Schema.Create(sysCtx); err != nil {
		t.Fatalf("schema create: %v", err)
	}

	if _, err := client.Tenant.Create().
		SetID(purgeTestTenant).
		SetName("Purge Tenant").
		SetSlug("purge-tenant").
		Save(sysCtx); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	if _, err := client.User.Create().
		SetID(purgeTestUser).
		SetTenantID(purgeTestTenant).
		SetEnvironment(user.EnvironmentTest).
		SetEmail("purge@example.com").
		Save(sysCtx); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	return NewRepository(factory), sysCtx, client
}

// sessionSpec describes one row to arrange. Zero times are left unset, which is
// how a session that was never rotated stores its grace timestamp.
type sessionSpec struct {
	id             string
	status         session.Status
	expiresAt      time.Time
	graceExpiresAt time.Time
}

func arrangeSessions(t *testing.T, ctx context.Context, client *ent.Client, specs ...sessionSpec) {
	t.Helper()

	for _, spec := range specs {
		create := client.Session.Create().
			SetID(spec.id).
			SetUserID(purgeTestUser).
			SetRefreshTokenHash("hash_" + spec.id).
			SetStatus(spec.status).
			SetExpiresAt(spec.expiresAt)
		if !spec.graceExpiresAt.IsZero() {
			create = create.SetGraceExpiresAt(spec.graceExpiresAt)
		}
		if _, err := create.Save(ctx); err != nil {
			t.Fatalf("arranging session %s: %v", spec.id, err)
		}
	}
}

func remainingIDs(t *testing.T, ctx context.Context, client *ent.Client) map[string]bool {
	t.Helper()

	ids, err := client.Session.Query().IDs(ctx)
	if err != nil {
		t.Fatalf("listing remaining sessions: %v", err)
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// TestPurgeExpiredSessionsKeepsWhatIsStillUseful is the core safety property.
// Two of these rows are dead but must survive: a superseded row inside its
// retention window is the only thing that turns a replayed refresh token into a
// theft alert rather than an anonymous 401, and a revoked row that has not yet
// reached its natural expiry is still the user's own sign-in history.
func TestPurgeExpiredSessionsKeepsWhatIsStillUseful(t *testing.T) {
	repo, ctx, client := setupPurgeTest(t)
	now := time.Now()

	arrangeSessions(t, ctx, client,
		sessionSpec{id: "ses_active", status: session.StatusActive, expiresAt: now.Add(30 * 24 * time.Hour)},
		sessionSpec{id: "ses_grace_fresh", status: session.StatusRotatedGrace, expiresAt: now.Add(30 * 24 * time.Hour), graceExpiresAt: now.Add(-time.Hour)},
		sessionSpec{id: "ses_grace_stale", status: session.StatusRotatedGrace, expiresAt: now.Add(30 * 24 * time.Hour), graceExpiresAt: now.Add(-96 * time.Hour)},
		sessionSpec{id: "ses_revoked_recent", status: session.StatusRevoked, expiresAt: now.Add(24 * time.Hour)},
		sessionSpec{id: "ses_expired_old", status: session.StatusActive, expiresAt: now.Add(-800 * time.Hour)},
	)

	removed, err := repo.PurgeExpiredSessions(ctx, now.Add(-72*time.Hour), now.Add(-720*time.Hour), 100)
	if err != nil {
		t.Fatalf("PurgeExpiredSessions: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed %d rows, want 2", removed)
	}

	left := remainingIDs(t, ctx, client)
	for _, id := range []string{"ses_active", "ses_grace_fresh", "ses_revoked_recent"} {
		if !left[id] {
			t.Errorf("%s was deleted; it is still needed", id)
		}
	}
	for _, id := range []string{"ses_grace_stale", "ses_expired_old"} {
		if left[id] {
			t.Errorf("%s survived the sweep", id)
		}
	}
}

// TestPurgeExpiredSessionsClearsABacklogAcrossBatches covers the case the
// batching exists for: the first sweep of a deployment that has never retained
// anything. The sweep must finish the table rather than stopping after one batch.
func TestPurgeExpiredSessionsClearsABacklogAcrossBatches(t *testing.T) {
	repo, ctx, client := setupPurgeTest(t)
	now := time.Now()

	const backlog = 7
	specs := make([]sessionSpec, 0, backlog)
	for i := range backlog {
		specs = append(specs, sessionSpec{
			id:        fmt.Sprintf("ses_old_%02d", i),
			status:    session.StatusActive,
			expiresAt: now.Add(-800 * time.Hour),
		})
	}
	arrangeSessions(t, ctx, client, specs...)

	removed, err := repo.PurgeExpiredSessions(ctx, now.Add(-72*time.Hour), now.Add(-720*time.Hour), 2)
	if err != nil {
		t.Fatalf("PurgeExpiredSessions: %v", err)
	}
	if removed != backlog {
		t.Errorf("removed %d rows with a batch size of 2, want %d", removed, backlog)
	}
	if left := remainingIDs(t, ctx, client); len(left) != 0 {
		t.Errorf("%d rows survived a completed sweep", len(left))
	}
}

// TestPurgeExpiredSessionsRejectsANonPositiveBatchSize keeps a misconfigured
// batch size from becoming a sweep that silently does nothing forever — a zero
// limit selects no rows, which is indistinguishable from an empty table.
func TestPurgeExpiredSessionsRejectsANonPositiveBatchSize(t *testing.T) {
	repo, ctx, _ := setupPurgeTest(t)
	now := time.Now()

	for _, batchSize := range []int{0, -10} {
		if _, err := repo.PurgeExpiredSessions(ctx, now, now, batchSize); err == nil {
			t.Errorf("batch size %d was accepted", batchSize)
		}
	}
}

// TestPurgeExpiredSessionsRequiresABypassContext pins the reason the sweeper
// wraps its context: the sweep spans tenants, and the privacy interceptor
// refuses an unscoped session query without an explicit bypass. A sweeper that
// forgot the wrapper would log failures rather than delete rows.
func TestPurgeExpiredSessionsRequiresABypassContext(t *testing.T) {
	repo, _, _ := setupPurgeTest(t)
	now := time.Now()

	_, err := repo.PurgeExpiredSessions(context.Background(), now, now, 100)
	if err == nil {
		t.Fatal("purge succeeded on a context with no privacy scope")
	}
	if !errors.Is(err, privacy.ErrPrivacyViolation) {
		t.Errorf("error = %v, want a privacy violation", err)
	}
}
