/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/retention_test.go
 * Tier: Unit Tests / Auth Retention
 *
 * Drives the idle test-user purge against a real database with foreign keys
 * enabled, because what the purge has to get right is the delete order: every
 * key into the users table is declared with no delete action, so a purge that
 * removed the account before its children would be refused by the database
 * rather than leaving anything behind. A test with foreign keys off would pass
 * while the shipped sweep failed on every row.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// purgeFixture is the account population one purge test runs against.
type purgeFixture struct {
	repo   *auth.Repository
	client *ent.Client
}

// newPurgeFixture opens an isolated database and returns a repository over it
// alongside a client for asserting what survived.
func newPurgeFixture(t *testing.T, tenantID string) purgeFixture {
	t.Helper()

	dsn := fmt.Sprintf("file:ent_idle_purge_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), tenantID))

	return purgeFixture{repo: repo, client: factory.GetClient(testCtx(), tenantID, "test")}
}

// createUser adds one account. A nil lastSignIn leaves the column unset, which is
// the state of an account that registered and never came back.
func (f purgeFixture) createUser(t *testing.T, tenantID string, env user.Environment, createdAt time.Time, lastSignIn *time.Time) string {
	t.Helper()

	id := idgen.New("usr")
	create := f.client.User.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetEmail(id + "@example.com").
		SetEnvironment(env).
		SetCreatedAt(createdAt)
	if lastSignIn != nil {
		create = create.SetLastSignInAt(*lastSignIn)
	}
	_, err := create.Save(testCtx())
	require.NoError(t, err)

	return id
}

// TestPurgeIdleTestUsersRemovesIdleTestAccountsOnly is the sweep's contract in
// one test: it takes idle test accounts, and it takes nothing else.
//
// The live account matters most. It is idle by exactly the same measure as the
// first test account, so a predicate that forgot the environment would delete a
// paying customer's account and the test would still look like it was about
// retention.
func TestPurgeIdleTestUsersRemovesIdleTestAccountsOnly(t *testing.T) {
	const tenantID = "tnt_idle_purge"
	f := newPurgeFixture(t, tenantID)

	now := time.Now()
	long, recent := now.Add(-40*24*time.Hour), now.Add(-time.Hour)

	idleTest := f.createUser(t, tenantID, user.EnvironmentTest, long, &long)
	neverSignedIn := f.createUser(t, tenantID, user.EnvironmentTest, long, nil)
	activeTest := f.createUser(t, tenantID, user.EnvironmentTest, long, &recent)
	freshTest := f.createUser(t, tenantID, user.EnvironmentTest, recent, nil)
	idleLive := f.createUser(t, tenantID, user.EnvironmentLive, long, &long)

	removed, err := f.repo.PurgeIdleTestUsers(testCtx(), now.Add(-30*24*time.Hour), 100)
	require.NoError(t, err)
	assert.Equal(t, 2, removed, "the two idle test accounts must be the only ones removed")

	survivors, err := f.client.User.Query().IDs(testCtx())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{activeTest, freshTest, idleLive}, survivors,
		"a live account, a recent sign-in and a fresh registration must all survive")
	assert.NotContains(t, survivors, idleTest)
	assert.NotContains(t, survivors, neverSignedIn)
}

// TestPurgeIdleTestUsersRemovesDependentRows checks the delete order against a
// real foreign key. Without it the account delete is refused and the sweep
// reports an error every time it runs.
func TestPurgeIdleTestUsersRemovesDependentRows(t *testing.T) {
	const tenantID = "tnt_idle_children"
	f := newPurgeFixture(t, tenantID)

	now := time.Now()
	long := now.Add(-40 * 24 * time.Hour)
	idle := f.createUser(t, tenantID, user.EnvironmentTest, long, &long)

	sessionID := idgen.New("ses")
	_, err := f.client.Session.Create().
		SetID(sessionID).
		SetUserID(idle).
		SetRefreshTokenHash("hash_" + sessionID).
		SetExpiresAt(now.Add(time.Hour)).
		Save(testCtx())
	require.NoError(t, err)

	// A row on the session rather than on the user, to confirm the purge reaches
	// the generation below the one it deletes. This key cascades, so the database
	// clears it when the session goes.
	appID := idgen.New("app")
	_, err = f.client.Application.Create().
		SetID(appID).
		SetTenantID(tenantID).
		SetName("idle purge fixture").
		SetEnvironment(application.EnvironmentTest).
		Save(testCtx())
	require.NoError(t, err)

	_, err = f.client.SessionAppActivity.Create().
		SetID(idgen.New("saa")).
		SetSessionID(sessionID).
		SetApplicationID(appID).
		Save(testCtx())
	require.NoError(t, err)

	_, err = f.client.TwoFactorMethod.Create().
		SetID(idgen.New("2fa")).
		SetUserID(idle).
		SetType("totp").
		SetSecretEncrypted("encrypted").
		Save(testCtx())
	require.NoError(t, err)

	removed, err := f.repo.PurgeIdleTestUsers(testCtx(), now.Add(-30*24*time.Hour), 100)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	remainingSessions, err := f.client.Session.Query().Where(session.UserID(idle)).Count(testCtx())
	require.NoError(t, err)
	assert.Zero(t, remainingSessions, "the account's sessions must go with it")

	remainingActivity, err := f.client.SessionAppActivity.Query().Count(testCtx())
	require.NoError(t, err)
	assert.Zero(t, remainingActivity, "session activity cascades from the session")

	remaining2FA, err := f.client.TwoFactorMethod.Query().Count(testCtx())
	require.NoError(t, err)
	assert.Zero(t, remaining2FA, "a surviving second factor would mean the delete order is wrong")
}

// TestPurgeIdleTestUsersBatchesUntilDrained checks that a backlog larger than one
// batch is cleared in full. The sweep runs on an interval, so a purge that stopped
// after its first batch would still shrink the table and would look correct for as
// long as the backlog kept growing more slowly than the interval.
func TestPurgeIdleTestUsersBatchesUntilDrained(t *testing.T) {
	const tenantID = "tnt_idle_batches"
	f := newPurgeFixture(t, tenantID)

	now := time.Now()
	long := now.Add(-40 * 24 * time.Hour)
	for i := 0; i < 7; i++ {
		f.createUser(t, tenantID, user.EnvironmentTest, long, &long)
	}

	removed, err := f.repo.PurgeIdleTestUsers(testCtx(), now.Add(-30*24*time.Hour), 2)
	require.NoError(t, err)
	assert.Equal(t, 7, removed)

	left, err := f.client.User.Query().Count(testCtx())
	require.NoError(t, err)
	assert.Zero(t, left)
}

// TestPurgeIdleTestUsersRejectsANonPositiveBatchSize refuses rather than looping
// forever on a Limit(0) query, which returns every row and would make the "batch"
// the whole table.
func TestPurgeIdleTestUsersRejectsANonPositiveBatchSize(t *testing.T) {
	f := newPurgeFixture(t, "tnt_idle_batchsize")

	_, err := f.repo.PurgeIdleTestUsers(testCtx(), time.Now(), 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch size")
}
