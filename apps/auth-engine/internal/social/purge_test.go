/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/purge_test.go
 * Tier: Social Identity Provider Layer / Tests
 *
 * Description: Covers the retention sweep over CSRF state rows. Abandoned
 *              sign-ins leave their state behind, so the sweep must clear an
 *              arbitrarily large backlog while leaving a round trip that is
 *              still in progress able to complete.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

const statePurgeTenant = "tnt_state_purge"

func setupStatePurgeTest(t *testing.T) (*Repository, context.Context, *ent.Client) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "social_state_purge_test_*")
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
	client := factory.GetClient(sysCtx, statePurgeTenant, "test")
	if err := client.Schema.Create(sysCtx); err != nil {
		t.Fatalf("schema create: %v", err)
	}

	if _, err := client.Tenant.Create().
		SetID(statePurgeTenant).
		SetName("State Purge Tenant").
		SetSlug("state-purge-tenant").
		Save(sysCtx); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	return NewRepository(factory, "0123456789abcdef0123456789abcdef"), sysCtx, client
}

// arrangeState writes one state row through the production writer, using the ttl
// sign to place it either side of the sweep cutoff.
func arrangeState(t *testing.T, ctx context.Context, repo *Repository, ttl time.Duration) string {
	t.Helper()

	token, err := repo.CreateSocialAuthState(ctx, statePurgeTenant, "app_state_purge", "test",
		"google", "https://app.example.com/cb", "", ttl)
	if err != nil {
		t.Fatalf("CreateSocialAuthState(ttl=%s): %v", ttl, err)
	}
	return token
}

// TestPurgeExpiredAuthStateSparesAFlowInProgress is the property that keeps the
// sweep from signing people out mid-login: a state row whose expiry has not
// passed belongs to a browser that may still be at the provider's consent screen.
func TestPurgeExpiredAuthStateSparesAFlowInProgress(t *testing.T) {
	repo, ctx, client := setupStatePurgeTest(t)

	liveToken := arrangeState(t, ctx, repo, 10*time.Minute)
	arrangeState(t, ctx, repo, -time.Hour)

	removed, err := repo.PurgeExpiredAuthState(ctx, time.Now(), 100)
	if err != nil {
		t.Fatalf("PurgeExpiredAuthState: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed %d rows, want 1", removed)
	}

	remaining, err := client.SocialAuthState.Query().IDs(ctx)
	if err != nil {
		t.Fatalf("listing remaining state: %v", err)
	}
	if len(remaining) != 1 || remaining[0] != liveToken {
		t.Errorf("remaining state = %v, want only the unexpired token", remaining)
	}
}

// TestPurgeExpiredAuthStateClearsABacklogAcrossBatches covers a deployment whose
// abandoned sign-ins have accumulated for longer than one batch can hold.
func TestPurgeExpiredAuthStateClearsABacklogAcrossBatches(t *testing.T) {
	repo, ctx, client := setupStatePurgeTest(t)

	const backlog = 5
	for range backlog {
		arrangeState(t, ctx, repo, -time.Hour)
	}

	removed, err := repo.PurgeExpiredAuthState(ctx, time.Now(), 2)
	if err != nil {
		t.Fatalf("PurgeExpiredAuthState: %v", err)
	}
	if removed != backlog {
		t.Errorf("removed %d rows with a batch size of 2, want %d", removed, backlog)
	}

	remaining, err := client.SocialAuthState.Query().IDs(ctx)
	if err != nil {
		t.Fatalf("listing remaining state: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d rows survived a completed sweep", len(remaining))
	}
}

func TestPurgeExpiredAuthStateRejectsANonPositiveBatchSize(t *testing.T) {
	repo, ctx, _ := setupStatePurgeTest(t)

	for _, batchSize := range []int{0, -10} {
		if _, err := repo.PurgeExpiredAuthState(ctx, time.Now(), batchSize); err == nil {
			t.Errorf("batch size %d was accepted", batchSize)
		}
	}
}

// TestPurgeExpiredAuthStateRequiresABypassContext mirrors the session sweep: the
// interceptor refuses an unscoped state query, so the sweeper's bypass wrapper is
// load-bearing rather than defensive.
func TestPurgeExpiredAuthStateRequiresABypassContext(t *testing.T) {
	repo, _, _ := setupStatePurgeTest(t)

	_, err := repo.PurgeExpiredAuthState(context.Background(), time.Now(), 100)
	if err == nil {
		t.Fatal("purge succeeded on a context with no privacy scope")
	}
	if !errors.Is(err, privacy.ErrPrivacyViolation) {
		t.Errorf("error = %v, want a privacy violation", err)
	}
}
