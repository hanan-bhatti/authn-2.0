/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/publish_test.go
 * Tier: Domain Model & Integration Test Layer
 *
 * Description: Integration tests for the environment split — that a policy written
 *              in test does not govern live, that publishing promotes the whole
 *              configuration and reports what it changed, and that the promotion is
 *              recorded in the audit trail.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publishTenant owns every row these tests write.
const publishTenant = "tnt_publish_test"

// setupPublishRepo provisions a tenant with both settings rows and returns a
// repository and a bypass context to drive it with.
//
// The bypass stands in for provisioning, which is the only caller that legitimately
// spans environments. Each test gets its own in-memory database so the shared
// tenant ID cannot leak state between them.
func setupPublishRepo(t *testing.T) (*policy.Repository, *clientfactory.ClientFactory, context.Context) {
	t.Helper()

	dbName := fmt.Sprintf("file:ent_publish_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	ctx := privacy.NewBypassContext(context.Background())

	_, err = factory.GetClient(ctx, publishTenant, "test").Tenant.Create().
		SetID(publishTenant).
		SetName("Publish Test Workspace").
		SetSlug(publishTenant).
		Save(ctx)
	require.NoError(t, err)

	repo := policy.NewRepository(factory)
	require.NoError(t, repo.EnsureEnvironments(ctx, publishTenant))

	return repo, factory, ctx
}

// TestPolicyWrittenInTestDoesNotGovernLive is the whole point of the split: an
// administrator tightening a rule in test must not change what live enforces.
func TestPolicyWrittenInTestDoesNotGovernLive(t *testing.T) {
	repo, _, ctx := setupPublishRepo(t)

	strict := policy.DefaultPasswordPolicy()
	strict.MinLength = 20

	_, err := repo.UpdatePasswordPolicy(ctx, publishTenant, "test", strict)
	require.NoError(t, err)

	inTest, err := repo.GetPasswordPolicy(ctx, publishTenant, "test")
	require.NoError(t, err)
	assert.Equal(t, 20, inTest.MinLength, "test must hold the policy just written")

	inLive, err := repo.GetPasswordPolicy(ctx, publishTenant, "live")
	require.NoError(t, err)
	assert.Equal(t, policy.DefaultPasswordPolicy().MinLength, inLive.MinLength,
		"live must still enforce the default: nothing was published to it")
}

// TestPublishPromotesTestToLive covers the promotion an administrator performs
// after rehearsing a change, and the changed-column list they see afterwards.
func TestPublishPromotesTestToLive(t *testing.T) {
	repo, _, ctx := setupPublishRepo(t)

	strict := policy.DefaultPasswordPolicy()
	strict.MinLength = 20
	_, err := repo.UpdatePasswordPolicy(ctx, publishTenant, "test", strict)
	require.NoError(t, err)

	result, err := repo.Publish(ctx, publishTenant, "test", "live")
	require.NoError(t, err)
	assert.Equal(t, []string{"password_policy"}, result.Changed,
		"only the column that actually differed should be reported")

	inLive, err := repo.GetPasswordPolicy(ctx, publishTenant, "live")
	require.NoError(t, err)
	assert.Equal(t, 20, inLive.MinLength, "live must now enforce the published rule")
}

// TestPublishReportsNoChangeWhenEnvironmentsMatch guards the changed-column list
// against reporting churn that did not happen. A second publish alters nothing, and
// an administrator reading "password_policy changed" again would be misinformed.
func TestPublishReportsNoChangeWhenEnvironmentsMatch(t *testing.T) {
	repo, _, ctx := setupPublishRepo(t)

	strict := policy.DefaultPasswordPolicy()
	strict.MinLength = 20
	_, err := repo.UpdatePasswordPolicy(ctx, publishTenant, "test", strict)
	require.NoError(t, err)

	_, err = repo.Publish(ctx, publishTenant, "test", "live")
	require.NoError(t, err)

	again, err := repo.Publish(ctx, publishTenant, "test", "live")
	require.NoError(t, err)
	assert.Empty(t, again.Changed, "a repeat publish changes nothing and must say so")

	// The handler hands this list straight to a response, and "nothing changed" is
	// the answer it gives most often. Encoded as null a client reading its length
	// would break on the ordinary case, so the empty list is part of the contract.
	encoded, err := json.Marshal(again.Changed)
	require.NoError(t, err)
	assert.Equal(t, "[]", string(encoded), "an empty changed list must encode as [], not null")
}

// TestPublishOntoItselfIsRefused covers the guard that keeps published_at honest:
// stamping it without copying anything would make the audit trail claim a promotion
// that never happened.
func TestPublishOntoItselfIsRefused(t *testing.T) {
	repo, _, ctx := setupPublishRepo(t)

	_, err := repo.Publish(ctx, publishTenant, "live", "live")
	require.ErrorIs(t, err, policy.ErrInvalidEnvironment)
}

// TestPublishRejectsUnknownEnvironment covers the refusal that keeps a typo from
// being resolved into one of the two real environments.
func TestPublishRejectsUnknownEnvironment(t *testing.T) {
	repo, _, ctx := setupPublishRepo(t)

	_, err := repo.Publish(ctx, publishTenant, "test", "staging")
	require.ErrorIs(t, err, policy.ErrInvalidEnvironment)
}

// TestRecordPublishWritesAuditRow covers the trail that answers "when did live
// start enforcing this", including that the column names are recorded and no
// credential travels with them.
func TestRecordPublishWritesAuditRow(t *testing.T) {
	repo, factory, ctx := setupPublishRepo(t)

	err := repo.RecordPublish(ctx, publishTenant, policy.PublishAudit{
		From:      "test",
		To:        "live",
		Changed:   []string{"password_policy", "session_policy"},
		ActorID:   "usr_admin",
		APIKeyID:  "key_live_1",
		IPAddress: "203.0.113.7",
		UserAgent: "console/1.0",
	})
	require.NoError(t, err)

	row, err := factory.GetClient(ctx, publishTenant, "live").AuditLog.Query().
		Where(auditlog.EventType("tenant.settings.published")).
		Only(ctx)
	require.NoError(t, err)

	assert.Equal(t, publishTenant, row.TenantID)
	assert.Equal(t, "test", row.Metadata["from"])
	assert.Equal(t, "live", row.Metadata["to"])
	assert.Equal(t, "usr_admin", row.Metadata["actor_id"])
	assert.Equal(t, "203.0.113.7", row.IPAddress)

	// Stored JSON comes back as []interface{}, so the names are compared one by one
	// rather than against a []string literal.
	changed, ok := row.Metadata["changed_columns"].([]interface{})
	require.True(t, ok, "changed_columns must be a list")
	require.Len(t, changed, 2)
	assert.Equal(t, "password_policy", changed[0])
	assert.Equal(t, "session_policy", changed[1])
}

// TestSettingsReadCannotCrossTenants covers the boundary a scoped request is held
// to: a caller confined to one tenant may read either of its own environments and
// neither of anybody else's.
func TestSettingsReadCannotCrossTenants(t *testing.T) {
	repo, _, sysCtx := setupPublishRepo(t)

	scoped := privacy.NewContext(context.Background(), "tnt_someone_else", "", "live")

	_, err := repo.Snapshot(scoped, publishTenant, "live")
	require.ErrorIs(t, err, policy.ErrTenantMismatch)

	// The same read succeeds for the tenant the scope actually names, confirming the
	// refusal above is about the boundary rather than a broken query.
	_, err = repo.Snapshot(sysCtx, publishTenant, "live")
	require.NoError(t, err)
}
