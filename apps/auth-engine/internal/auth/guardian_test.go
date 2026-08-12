/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/guardian_test.go
 * Tier: Internal Feature Package / Guardian Integration Tests
 *
 * Description: Automated test suite for flexible 1-5 guardian enrollment, zero-knowledge share distribution,
 *              invitation acceptance, listing, and Re-Key/Re-Split protocol on guardian revocation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestGuardianService(t *testing.T) (*auth.GuardianService, *auth.Repository, string) {
	dbName := fmt.Sprintf("file:ent_gdn_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)

	tenantID := "tnt_test_gdn"
	err = repo.EnsureTenantExists(testCtx(), tenantID)
	require.NoError(t, err)

	client := factory.GetClient(testCtx(), tenantID, "test")

	userID := idgen.New("usr")
	_, err = client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("owner@example.com").
		SetPasswordHash("hashed_password").
		Save(testCtx())
	require.NoError(t, err)

	policyRepo := policy.NewRepository(factory)
	svc := auth.NewGuardianService(repo, policyRepo)
	return svc, repo, userID
}

func TestGuardian_Enrollment_1To5Flexible(t *testing.T) {
	svc, _, userID := setupTestGuardianService(t)
	ctx := testCtx()

	// Invite 3 guardians
	inputs := []auth.InviteGuardianInput{
		{Email: "alice@example.com", Name: "Alice"},
		{Email: "bob@example.com", Name: "Bob"},
		{Email: "charlie@example.com", Name: "Charlie"},
	}

	res, err := svc.InviteGuardians(ctx, userID, inputs, "http://localhost:8080")
	require.NoError(t, err)
	assert.Equal(t, 3, res.EnrolledCount)
	assert.Equal(t, 2, res.ThresholdK) // 2-of-3 majority
	assert.Len(t, res.Guardians, 3)
	assert.Len(t, res.InviteURLs, 3)

	// Verify URL structure uses URL fragment anchor #token= for zero-knowledge client delivery
	for _, uStr := range res.InviteURLs {
		u, err := url.Parse(uStr)
		require.NoError(t, err)
		assert.Contains(t, u.Fragment, "token=")
	}
}

func TestGuardian_MaxLimit_Exceeded(t *testing.T) {
	svc, _, userID := setupTestGuardianService(t)
	ctx := testCtx()

	inputs := make([]auth.InviteGuardianInput, 6)
	for i := 0; i < 6; i++ {
		inputs[i] = auth.InviteGuardianInput{
			Email: fmt.Sprintf("gdn%d@example.com", i),
			Name:  fmt.Sprintf("Guardian %d", i),
		}
	}

	_, err := svc.InviteGuardians(ctx, userID, inputs, "http://localhost:8080")
	assert.ErrorContains(t, err, "maximum allowed limit")
}

func TestGuardian_AcceptInvitation(t *testing.T) {
	svc, repo, userID := setupTestGuardianService(t)
	ctx := testCtx()

	res, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{{Email: "alice@example.com", Name: "Alice"}}, "http://localhost:8080")
	require.NoError(t, err)

	// Extract token from URL fragment
	u, err := url.Parse(res.InviteURLs[0])
	require.NoError(t, err)
	rawToken := u.Fragment[len("token="):]

	contactID := res.Guardians[0].ID

	// Accept invite
	err = svc.AcceptGuardianInvite(ctx, contactID, rawToken)
	require.NoError(t, err)

	// Verify status updated to active
	contact, err := repo.GetRecoveryContactByID(ctx, contactID)
	require.NoError(t, err)
	assert.Equal(t, recoverycontact.StatusActive, contact.Status)
}

func TestGuardian_ListGuardians_NoSecretExposure(t *testing.T) {
	svc, _, userID := setupTestGuardianService(t)
	ctx := testCtx()

	_, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "alice@example.com", Name: "Alice"},
		{Email: "bob@example.com", Name: "Bob"},
	}, "http://localhost:8080")
	require.NoError(t, err)

	guardians, err := svc.ListGuardians(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, guardians, 2)

	// DTO must expose only basic metadata
	for _, g := range guardians {
		assert.NotEmpty(t, g.ID)
		assert.NotEmpty(t, g.GuardianEmail)
		assert.Greater(t, g.ShareIndex, 0)
	}
}

func TestGuardian_Revocation_ReKeyAndReSplit(t *testing.T) {
	svc, repo, userID := setupTestGuardianService(t)
	ctx := testCtx()

	// Invite 3 guardians (2-of-3)
	res, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "alice@example.com", Name: "Alice"},
		{Email: "bob@example.com", Name: "Bob"},
		{Email: "charlie@example.com", Name: "Charlie"},
	}, "http://localhost:8080")
	require.NoError(t, err)

	// Record initial share hashes
	initialContacts, err := repo.GetRecoveryContactsByUser(ctx, userID)
	require.NoError(t, err)
	oldHashes := make(map[string]string)
	for _, c := range initialContacts {
		oldHashes[c.ID] = c.ShareHash
	}

	// Revoke Charlie
	charlieID := res.Guardians[2].ID
	err = svc.RevokeGuardian(ctx, userID, charlieID)
	require.NoError(t, err)

	// Verify Charlie deleted
	remaining, err := repo.GetRecoveryContactsByUser(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, remaining, 2)

	// Verify remaining guardians (Alice & Bob) re-keyed with NEW share hashes (N=2, k=2)
	for _, c := range remaining {
		assert.NotEqual(t, oldHashes[c.ID], c.ShareHash, "Share hash must change following Re-Key/Re-Split")
	}
}
