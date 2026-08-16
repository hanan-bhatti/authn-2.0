//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/session_app_activity_test.go
 * Tier: Integration Test
 *
 * Covers the storage guarantees behind per-application session activity, and
 * the two User columns that admin lifecycle actions will depend on.
 *
 * These properties are enforced by the database and the privacy interceptor
 * rather than by any handler, so they are exercised directly against the Ent
 * client. A handler test would prove only that today's single writer happens to
 * behave; these prove that a second writer added later is still held to the
 * same shape.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// victimApplication is the second tenant's application, used to build a
// pairing that straddles the tenant boundary.
const victimApplication = "app_00000000000000000000000000000099"

// client returns an Ent client for direct reads and writes under ctx. The
// tenant and environment arguments only pick a connection pool; scoping comes
// from the context.
func (e *testEnv) client(ctx context.Context) *ent.Client {
	return e.factory.GetClient(ctx, testTenant, testEnvironment)
}

// seedUser creates a user directly, without going through sign-up.
//
// Sign-up would work, but it hashes a password with Argon2id — hundreds of
// milliseconds per call, for a row these tests only need as the parent a
// session hangs from.
func (e *testEnv) seedUser(t *testing.T, tenantID, userID, email string) {
	t.Helper()
	ctx := e.bypassContext()
	if _, err := e.client(ctx).User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEnvironment(testEnvironment).
		SetEmail(email).
		Save(ctx); err != nil {
		t.Fatalf("seeding user %s: %v", userID, err)
	}
}

// seedSession creates an active session owned by userID.
func (e *testEnv) seedSession(t *testing.T, sessionID, userID string) {
	t.Helper()
	ctx := e.bypassContext()
	if _, err := e.client(ctx).Session.Create().
		SetID(sessionID).
		SetUserID(userID).
		// Unique across the table, so it is derived from the session ID rather
		// than shared between fixtures.
		SetRefreshTokenHash("hash_" + sessionID).
		SetExpiresAt(time.Now().Add(time.Hour)).
		Save(ctx); err != nil {
		t.Fatalf("seeding session %s: %v", sessionID, err)
	}
}

// seedActivity records one use of a session at an application.
func (e *testEnv) seedActivity(t *testing.T, activityID, sessionID, appID string) {
	t.Helper()
	ctx := e.bypassContext()
	if _, err := e.client(ctx).SessionAppActivity.Create().
		SetID(activityID).
		SetSessionID(sessionID).
		SetApplicationID(appID).
		Save(ctx); err != nil {
		t.Fatalf("seeding activity %s: %v", activityID, err)
	}
}

// countActivity returns how many activity rows exist, unfiltered by tenant.
func (e *testEnv) countActivity(t *testing.T) int {
	t.Helper()
	ctx := e.bypassContext()
	count, err := e.client(ctx).SessionAppActivity.Query().Count(ctx)
	if err != nil {
		t.Fatalf("counting activity rows: %v", err)
	}
	return count
}

// TestActivityIsOneRowPerSessionAndApplication writes the same pairing twice.
//
// Every writer of these rows upserts on the pair, so the constraint is what
// makes that upsert safe: without it two concurrent requests from one session
// both insert, and the application ends up with two rows whose timestamps each
// describe half of the session's traffic.
func TestActivityIsOneRowPerSessionAndApplication(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedUser(t, testTenant, "usr_activity_owner", "owner@activity.example")
	env.seedSession(t, "ses_activity_owner", "usr_activity_owner")
	env.seedActivity(t, "saa_first", "ses_activity_owner", testApplication)

	ctx := env.bypassContext()
	_, err := env.client(ctx).SessionAppActivity.Create().
		SetID("saa_duplicate").
		SetSessionID("ses_activity_owner").
		SetApplicationID(testApplication).
		Save(ctx)
	if err == nil {
		t.Fatal("a second activity row for the same session and application was accepted")
	}
	if !ent.IsConstraintError(err) {
		t.Fatalf("duplicate pairing was refused for the wrong reason: %v", err)
	}

	if got := env.countActivity(t); got != 1 {
		t.Fatalf("activity rows after the refused duplicate: got %d, want 1", got)
	}
}

// TestActivityNeedsBothParentsInTenant reads activity rows under a tenant scope.
//
// The interceptor joins through the session and the application, so a row is
// visible only when both parents belong to the caller. The case that
// distinguishes that from joining through either one alone is a pairing that
// straddles the boundary: nothing should be able to write one, but if something
// did, a single-parent filter would show it to one of the two tenants as
// though it were their own.
func TestActivityNeedsBothParentsInTenant(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)
	if err := env.authRepo.EnsureDefaultApplicationExists(env.bypassContext(),
		victimApplication, victimTenant, []string{"http://localhost:4000/callback"}); err != nil {
		t.Fatalf("seeding victim application: %v", err)
	}

	env.seedUser(t, testTenant, "usr_own", "own@activity.example")
	env.seedSession(t, "ses_own", "usr_own")
	env.seedUser(t, victimTenant, "usr_victim", "victim@activity.example")
	env.seedSession(t, "ses_victim", "usr_victim")

	// One well-formed pairing per tenant, plus one that crosses.
	env.seedActivity(t, "saa_own", "ses_own", testApplication)
	env.seedActivity(t, "saa_victim", "ses_victim", victimApplication)
	env.seedActivity(t, "saa_crossed", "ses_own", victimApplication)

	for _, tc := range []struct {
		tenant string
		want   string
	}{
		{tenant: testTenant, want: "saa_own"},
		{tenant: victimTenant, want: "saa_victim"},
	} {
		scoped := privacy.NewContext(context.Background(), tc.tenant, "", testEnvironment)
		rows, err := env.client(scoped).SessionAppActivity.Query().All(scoped)
		if err != nil {
			t.Fatalf("reading activity as tenant %s: %v", tc.tenant, err)
		}
		if len(rows) != 1 {
			ids := make([]string, 0, len(rows))
			for _, row := range rows {
				ids = append(ids, row.ID)
			}
			t.Fatalf("tenant %s sees activity rows %v, want only %s", tc.tenant, ids, tc.want)
		}
		if rows[0].ID != tc.want {
			t.Fatalf("tenant %s sees activity row %s, want %s", tc.tenant, rows[0].ID, tc.want)
		}
	}
}

// TestActivityQueryWithoutTenantIsRefused reads activity with no scope in
// context.
//
// Fail-closed is the interceptor's contract for every entity, and it is what
// makes an unscoped query a loud error rather than a cross-tenant read.
func TestActivityQueryWithoutTenantIsRefused(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	unscoped := context.Background()
	_, err := env.client(unscoped).SessionAppActivity.Query().All(unscoped)
	if err == nil {
		t.Fatal("an activity query with no tenant in context was allowed to run")
	}
	if !errors.Is(err, privacy.ErrPrivacyViolation) {
		t.Fatalf("unscoped activity query failed for the wrong reason: %v", err)
	}
}

// TestActivityDiesWithItsSession deletes a session that has activity rows.
//
// Revoking or deleting a session has to take its activity with it. A row left
// behind would keep reporting a session that no longer exists at an
// application, and nothing in the engine sweeps for such rows.
func TestActivityDiesWithItsSession(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedUser(t, testTenant, "usr_cascade_session", "cascade-session@activity.example")
	env.seedSession(t, "ses_cascade", "usr_cascade_session")
	env.seedActivity(t, "saa_cascade_session", "ses_cascade", testApplication)

	ctx := env.bypassContext()
	if err := env.client(ctx).Session.DeleteOneID("ses_cascade").Exec(ctx); err != nil {
		t.Fatalf("deleting session with activity: %v", err)
	}

	if got := env.countActivity(t); got != 0 {
		t.Fatalf("activity rows surviving their session: got %d, want 0", got)
	}
}

// TestActivityDiesWithItsApplication deletes an application that has activity
// rows.
//
// The application is created here rather than reused, because the seeded one
// owns the publishable key and its own foreign key would refuse the delete for
// an unrelated reason.
func TestActivityDiesWithItsApplication(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedUser(t, testTenant, "usr_cascade_app", "cascade-app@activity.example")
	env.seedSession(t, "ses_cascade_app", "usr_cascade_app")

	const secondApp = "app_00000000000000000000000000000002"
	if err := env.authRepo.EnsureDefaultApplicationExists(env.bypassContext(),
		secondApp, testTenant, []string{"http://localhost:3000/second"}); err != nil {
		t.Fatalf("seeding second application: %v", err)
	}
	env.seedActivity(t, "saa_cascade_app", "ses_cascade_app", secondApp)

	ctx := env.bypassContext()
	if err := env.client(ctx).Application.DeleteOneID(secondApp).Exec(ctx); err != nil {
		t.Fatalf("deleting application with activity: %v", err)
	}

	if got := env.countActivity(t); got != 0 {
		t.Fatalf("activity rows surviving their application: got %d, want 0", got)
	}
}

// TestSuspendedStatusRoundTrips stores and reads back the suspended status.
//
// It is a new value on an existing enum, so the check worth making is that the
// column accepts it at all: an enum the generated code knows about but the
// stored column does not would fail only on the first suspension in
// production.
func TestSuspendedStatusRoundTrips(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedUser(t, testTenant, "usr_suspend", "suspend@activity.example")

	ctx := env.bypassContext()
	if err := env.client(ctx).User.UpdateOneID("usr_suspend").
		SetStatus("suspended").
		Exec(ctx); err != nil {
		t.Fatalf("suspending user: %v", err)
	}

	stored, err := env.client(ctx).User.Get(ctx, "usr_suspend")
	if err != nil {
		t.Fatalf("reading suspended user: %v", err)
	}
	if stored.Status != "suspended" {
		t.Fatalf("stored status is %q, want suspended", stored.Status)
	}
}

// TestSoftDeletedUserKeepsEmailReserved signs an address up again after the
// first account holding it was soft-deleted.
//
// Keeping the address reserved is the point of soft deletion here: the row
// stays, so the unique index refuses the second signup. Without it, deleting an
// account would free the address for anyone to claim, and mail already in
// flight for the old account — a password reset, an invitation — would land in
// the new owner's inbox.
func TestSoftDeletedUserKeepsEmailReserved(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	const reserved = "reserved@activity.example"
	env.seedUser(t, testTenant, "usr_deleted", reserved)

	ctx := env.bypassContext()
	if err := env.client(ctx).User.UpdateOneID("usr_deleted").
		SetDeletedAt(time.Now()).
		Exec(ctx); err != nil {
		t.Fatalf("soft-deleting user: %v", err)
	}

	_, err := env.client(ctx).User.Create().
		SetID("usr_second_claim").
		SetTenantID(testTenant).
		SetEnvironment(testEnvironment).
		SetEmail(reserved).
		Save(ctx)
	if err == nil {
		t.Fatalf("address %s was claimed again while the soft-deleted row still holds it", reserved)
	}
	if !ent.IsConstraintError(err) {
		t.Fatalf("second claim on a reserved address was refused for the wrong reason: %v", err)
	}
}
