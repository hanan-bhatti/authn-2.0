//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/privacy_write_boundary_test.go
 * Tier: Integration Test
 *
 * Covers the write half of the privacy interceptor: the tenant a row is created
 * in must be the tenant the caller's context is scoped to.
 *
 * These tests sit below the HTTP layer on purpose. The handler tests in
 * tenant_isolation_test.go prove that no current route hands a request-supplied
 * tenant to the database; these prove that a route which did would still be
 * refused, so the guarantee does not depend on every future handler getting it
 * right.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"errors"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// TestCreateRefusesTenantOutsideContext writes a row naming one tenant from a
// context scoped to another.
//
// The interceptor stamps the caller's tenant onto rows that leave it unset, so
// the case that matters is the one it cannot stamp: a tenant that is already
// filled in and disagrees.
func TestCreateRefusesTenantOutsideContext(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)

	scoped := privacy.NewContext(env.bypassContext(), testTenant, "", testEnvironment)
	_, err := env.factory.GetClient(scoped, testTenant, testEnvironment).
		User.Create().
		SetID("usr_boundary_probe").
		SetTenantID(victimTenant).
		SetEnvironment("test").
		SetEmail("probe@victim-tenant.example").
		SetPasswordHash("argon2id$placeholder$hash").
		Save(scoped)
	if err == nil {
		t.Fatalf("creating a user in tenant %s succeeded from a context scoped to %s",
			victimTenant, testTenant)
	}
	if !errors.Is(err, privacy.ErrPrivacyViolation) {
		t.Fatalf("write across tenants was refused for the wrong reason: %v", err)
	}

	// The refusal must also mean nothing was written.
	count, err := env.factory.GetClient(env.bypassContext(), victimTenant, testEnvironment).
		User.Query().All(env.bypassContext())
	if err != nil {
		t.Fatalf("counting victim users: %v", err)
	}
	if len(count) != 0 {
		t.Fatalf("victim tenant holds %d users after a refused write", len(count))
	}
}

// TestCreateStampsTenantFromContext confirms the refusal above did not come at
// the cost of the stamping the rest of the codebase relies on: a create that
// names no tenant still inherits the caller's.
func TestCreateStampsTenantFromContext(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	scoped := privacy.NewContext(env.bypassContext(), testTenant, "", testEnvironment)
	created, err := env.factory.GetClient(scoped, testTenant, testEnvironment).
		User.Create().
		SetID("usr_stamp_probe").
		SetEnvironment("test").
		SetEmail("stamp@example.com").
		SetPasswordHash("argon2id$placeholder$hash").
		Save(scoped)
	if err != nil {
		t.Fatalf("creating a user with no tenant named: %v", err)
	}
	if created.TenantID != testTenant {
		t.Fatalf("row landed in tenant %q, want the context's %q", created.TenantID, testTenant)
	}
}

// TestUpdateDoesNotMoveRowBetweenTenants covers the other direction: an update
// that does not mention the tenant must leave it alone.
//
// Stamping the context's tenant onto an update would rewrite the tenant column
// of whichever row the predicate matched, which turns an ordinary field edit
// into a row moving between customers.
func TestUpdateDoesNotMoveRowBetweenTenants(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)

	ctx := env.bypassContext()
	victimUser, err := env.authRepo.CreateUser(ctx, "usr_victim_update_target",
		victimTenant, testEnvironment, "target@victim-tenant.example",
		"argon2id$placeholder$hash", "Victim Target", "")
	if err != nil {
		t.Fatalf("seeding victim user: %v", err)
	}

	// The update runs under a context for the other tenant and names only a
	// non-tenant field, which is how every ordinary edit reaches the database.
	scoped := privacy.NewContext(ctx, testTenant, "", testEnvironment)
	_, _ = env.factory.GetClient(scoped, testTenant, testEnvironment).
		User.UpdateOneID(victimUser.ID).
		SetName("Renamed By Another Tenant").
		Save(scoped)

	after, err := env.factory.GetClient(ctx, victimTenant, testEnvironment).
		User.Get(ctx, victimUser.ID)
	if err != nil {
		t.Fatalf("re-reading victim user: %v", err)
	}
	if after.TenantID != victimTenant {
		t.Fatalf("user moved from tenant %q to %q by an update from another tenant's context",
			victimTenant, after.TenantID)
	}
}
