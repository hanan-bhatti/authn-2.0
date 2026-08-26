/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/guardian_test.go
 * Tier: Internal Feature Package / Guardian Integration Tests
 *
 * Description: Automated test suite for flexible 1-5 guardian enrollment, one-time share delivery over
 *              the invitation link, invitation acceptance, listing, and revocation.
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
	assert.Len(t, res.Invites, 3)

	// Both secrets ride in the URL fragment, which a browser never sends to a server, and each
	// invite names the guardian it belongs to so a caller cannot send the wrong person a share.
	seenShares := map[string]bool{}
	for i, invite := range res.Invites {
		assert.Equal(t, inputs[i].Email, invite.GuardianEmail)
		assert.Equal(t, res.Guardians[i].ID, invite.ContactID)

		u, err := url.Parse(invite.URL)
		require.NoError(t, err)
		assert.Empty(t, u.Query().Get("token"), "the token must not appear in the query string")
		assert.Empty(t, u.Query().Get("share"), "the share must not appear in the query string")

		values, err := url.ParseQuery(u.Fragment)
		require.NoError(t, err)
		assert.Len(t, values.Get("token"), 64, "a 32-byte invite token in hex")

		share := values.Get("share")
		assert.Len(t, share, 64, "a 32-byte guardian share in hex")
		assert.False(t, seenShares[share], "each guardian must get an independent share")
		seenShares[share] = true
	}
}

// Enrolling a guardian must not disturb the shares already delivered to the others: those copies sit
// in inboxes the engine cannot reach, so rewriting the stored digests would silently un-enrol
// everyone already on the roster.
func TestGuardian_Enrollment_LeavesExistingSharesIntact(t *testing.T) {
	svc, repo, userID := setupTestGuardianService(t)
	ctx := testCtx()

	first, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "alice@example.com", Name: "Alice"},
	}, "http://localhost:8080")
	require.NoError(t, err)

	aliceToken, aliceShare := fragmentSecrets(t, first.Invites[0].URL)
	before, err := repo.GetRecoveryContactByID(ctx, first.Invites[0].ContactID)
	require.NoError(t, err)

	_, err = svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "bob@example.com", Name: "Bob"},
	}, "http://localhost:8080")
	require.NoError(t, err)

	after, err := repo.GetRecoveryContactByID(ctx, first.Invites[0].ContactID)
	require.NoError(t, err)
	assert.Equal(t, before.ShareHash, after.ShareHash, "Alice's stored share must not change")
	assert.Equal(t, before.ShareIndex, after.ShareIndex, "Alice's slot must not be renumbered")

	// The link Alice was sent before Bob existed still works.
	require.NoError(t, svc.AcceptGuardianInvite(ctx, first.Invites[0].ContactID, aliceToken, aliceShare))
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

// fragmentSecrets pulls a guardian's token and share out of their invitation link, which is the only
// place either value exists once the request that minted them has returned.
func fragmentSecrets(t *testing.T, rawURL string) (token, share string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	values, err := url.ParseQuery(u.Fragment)
	require.NoError(t, err)
	return values.Get("token"), values.Get("share")
}

func TestGuardian_AcceptInvitation(t *testing.T) {
	svc, repo, userID := setupTestGuardianService(t)
	ctx := testCtx()

	res, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{{Email: "alice@example.com", Name: "Alice"}}, "http://localhost:8080")
	require.NoError(t, err)

	contactID := res.Invites[0].ContactID
	token, share := fragmentSecrets(t, res.Invites[0].URL)

	err = svc.AcceptGuardianInvite(ctx, contactID, token, share)
	require.NoError(t, err)

	// Verify status updated to active
	contact, err := repo.GetRecoveryContactByID(ctx, contactID)
	require.NoError(t, err)
	assert.Equal(t, recoverycontact.StatusActive, contact.Status)
}

// A link that lost its fragment in transit is caught at acceptance, not during a lockout. Enrollment
// is the last moment the account holder can still fix it by re-inviting.
func TestGuardian_AcceptInvitation_RejectsMissingOrWrongShare(t *testing.T) {
	svc, repo, userID := setupTestGuardianService(t)
	ctx := testCtx()

	res, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{{Email: "alice@example.com", Name: "Alice"}}, "http://localhost:8080")
	require.NoError(t, err)

	contactID := res.Invites[0].ContactID
	token, share := fragmentSecrets(t, res.Invites[0].URL)

	err = svc.AcceptGuardianInvite(ctx, contactID, token, "")
	assert.ErrorIs(t, err, auth.ErrInvalidGuardianShare)

	err = svc.AcceptGuardianInvite(ctx, contactID, token, share[:len(share)-2]+"00")
	assert.ErrorIs(t, err, auth.ErrInvalidGuardianShare)

	// A right share with the wrong token is still refused, and on the token.
	err = svc.AcceptGuardianInvite(ctx, contactID, "deadbeef", share)
	assert.ErrorIs(t, err, auth.ErrInvalidInviteToken)

	contact, err := repo.GetRecoveryContactByID(ctx, contactID)
	require.NoError(t, err)
	assert.Equal(t, recoverycontact.StatusPendingInvite, contact.Status, "a failed acceptance must not activate the guardian")
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

// Revoking a guardian removes exactly that guardian. The survivors keep the shares already in their
// hands, and the threshold falls out of the smaller roster on its own.
func TestGuardian_Revocation_LeavesSurvivorsUsable(t *testing.T) {
	svc, repo, userID := setupTestGuardianService(t)
	ctx := testCtx()

	// Invite 3 guardians (2-of-3)
	res, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "alice@example.com", Name: "Alice"},
		{Email: "bob@example.com", Name: "Bob"},
		{Email: "charlie@example.com", Name: "Charlie"},
	}, "http://localhost:8080")
	require.NoError(t, err)

	initialContacts, err := repo.GetRecoveryContactsByUser(ctx, userID)
	require.NoError(t, err)
	oldHashes := make(map[string]string)
	for _, c := range initialContacts {
		oldHashes[c.ID] = c.ShareHash
	}

	aliceToken, aliceShare := fragmentSecrets(t, res.Invites[0].URL)

	// Revoke Charlie
	charlieID := res.Invites[2].ContactID
	err = svc.RevokeGuardian(ctx, userID, charlieID)
	require.NoError(t, err)

	remaining, err := repo.GetRecoveryContactsByUser(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, remaining, 2)

	for _, c := range remaining {
		assert.Equal(t, oldHashes[c.ID], c.ShareHash, "a survivor's share must keep working after a revocation")
	}

	// The link Alice was sent before Charlie was removed still accepts.
	require.NoError(t, svc.AcceptGuardianInvite(ctx, res.Invites[0].ContactID, aliceToken, aliceShare))

	// Two guardians left, so consensus is now 2-of-2 rather than the 2-of-3 it was.
	k, err := auth.CalculateThreshold(len(remaining))
	require.NoError(t, err)
	assert.Equal(t, 2, k)
}

// The revoked guardian's slot is left empty rather than renumbered, so the next enrollment fills the
// hole without touching a survivor's row — which is what keeps their saved share valid.
func TestGuardian_Revocation_ThenReinviteReusesTheFreedSlot(t *testing.T) {
	svc, repo, userID := setupTestGuardianService(t)
	ctx := testCtx()

	res, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "alice@example.com", Name: "Alice"},
		{Email: "bob@example.com", Name: "Bob"},
		{Email: "charlie@example.com", Name: "Charlie"},
	}, "http://localhost:8080")
	require.NoError(t, err)

	bobID := res.Invites[1].ContactID
	bobSlot := res.Guardians[1].ShareIndex
	require.NoError(t, svc.RevokeGuardian(ctx, userID, bobID))

	replacement, err := svc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "dana@example.com", Name: "Dana"},
	}, "http://localhost:8080")
	require.NoError(t, err)
	assert.Equal(t, bobSlot, replacement.Guardians[0].ShareIndex, "the freed slot is reused")

	// Charlie, who was enrolled after Bob, is untouched by the churn.
	charlie, err := repo.GetRecoveryContactByID(ctx, res.Invites[2].ContactID)
	require.NoError(t, err)
	assert.Equal(t, res.Guardians[2].ShareIndex, charlie.ShareIndex)

	charlieToken, charlieShare := fragmentSecrets(t, res.Invites[2].URL)
	require.NoError(t, svc.AcceptGuardianInvite(ctx, charlie.ID, charlieToken, charlieShare))
}
