/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/claim_test.go
 * Tier: Security & Authorization Layer / Tests
 *
 * Description: Tests for JWT console role-claim resolution.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"
	"testing"

	"entgo.io/ent/dialect"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/enttest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"

	_ "github.com/mattn/go-sqlite3"
)

// newClaimTestEnv returns an in-memory client plus a privacy-bypass context,
// with the tenant every role and user row hangs off already seeded.
func newClaimTestEnv(t *testing.T, dsn string) (*ent.Client, context.Context) {
	t.Helper()
	client := enttest.Open(t, dialect.SQLite,
		"file:"+dsn+"?mode=memory&cache=shared&_fk=1")
	ctx := privacy.NewBypassContext(context.Background())

	if _, err := client.Tenant.Create().
		SetID("tnt_00000000000000000000000000000001").
		SetName("Claim Test Tenant").
		SetSlug("claim-test").
		Save(ctx); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return client, ctx
}

// seedUserWithRole creates a user, a role with the given slug, and binds them.
func seedUserWithRole(t *testing.T, client *ent.Client, ctx context.Context, userID, roleSlug string) {
	t.Helper()

	if _, err := client.User.Create().
		SetID(userID).
		SetTenantID("tnt_00000000000000000000000000000001").
		SetEnvironment("test").
		SetEmail(userID + "@authn.local").
		SetName(userID).
		Save(ctx); err != nil {
		t.Fatalf("seed user %q: %v", userID, err)
	}

	r, err := client.Role.Create().
		SetID("rol_" + roleSlug).
		SetName(roleSlug).
		SetSlug(roleSlug).
		SetTenantID("tnt_00000000000000000000000000000001").
		Save(ctx)
	if err != nil {
		t.Fatalf("seed role %q: %v", roleSlug, err)
	}

	if _, err := client.UserRole.Create().
		SetID("ur_" + userID + "_" + roleSlug).
		SetUserID(userID).
		SetRoleID(r.ID).
		Save(ctx); err != nil {
		t.Fatalf("bind role %q to %q: %v", roleSlug, userID, err)
	}
}

func TestResolveConsoleRoleClaim(t *testing.T) {
	t.Run("tenant_admin resolves to the console claim", func(t *testing.T) {
		client, ctx := newClaimTestEnv(t, "claim_admin")
		defer client.Close()
		seedUserWithRole(t, client, ctx, "usr_admin", "tenant_admin")

		if got := ResolveConsoleRoleClaim(ctx, client, "usr_admin"); got != ConsoleRoleSlug {
			t.Errorf("got %q, want %q — a tenant admin must keep console access on every login", got, ConsoleRoleSlug)
		}
	})

	t.Run("non-admin role resolves to empty", func(t *testing.T) {
		client, ctx := newClaimTestEnv(t, "claim_viewer")
		defer client.Close()
		seedUserWithRole(t, client, ctx, "usr_viewer", "viewer")

		if got := ResolveConsoleRoleClaim(ctx, client, "usr_viewer"); got != "" {
			t.Errorf("got %q, want \"\" — a viewer must never receive a console claim", got)
		}
	})

	t.Run("org_admin does not grant console access", func(t *testing.T) {
		client, ctx := newClaimTestEnv(t, "claim_orgadmin")
		defer client.Close()
		seedUserWithRole(t, client, ctx, "usr_orgadmin", "org_admin")

		if got := ResolveConsoleRoleClaim(ctx, client, "usr_orgadmin"); got != "" {
			t.Errorf("got %q, want \"\" — org_admin is org-scoped, not tenant console", got)
		}
	})

	t.Run("user with no roles resolves to empty", func(t *testing.T) {
		client, ctx := newClaimTestEnv(t, "claim_nobody")
		defer client.Close()

		if got := ResolveConsoleRoleClaim(ctx, client, "usr_nobody"); got != "" {
			t.Errorf("got %q, want \"\"", got)
		}
	})

	t.Run("fails closed on empty user and nil client", func(t *testing.T) {
		client, ctx := newClaimTestEnv(t, "claim_failclosed")
		defer client.Close()

		if got := ResolveConsoleRoleClaim(ctx, client, ""); got != "" {
			t.Errorf("empty userID: got %q, want \"\"", got)
		}
		if got := ResolveConsoleRoleClaim(ctx, nil, "usr_admin"); got != "" {
			t.Errorf("nil client: got %q, want \"\"", got)
		}
	})
}
