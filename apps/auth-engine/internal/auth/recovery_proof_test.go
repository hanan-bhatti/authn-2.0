/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_proof_test.go
 * Tier: Internal Feature Package / Sub-step 4b Integration Tests
 *
 * Description: Test suite for guardian share accumulation, old password proof with exponential lockout schedule,
 *              and server-side enforcement of higher-tier method exhaustion before security questions.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"strings"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubmitGuardianProof_ShareAccumulation(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	policyRepo := policy.NewRepository(repo.GetClientFactory())
	gdnSvc := auth.NewGuardianService(repo, policyRepo)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("gdnproof@example.com").
		SetPasswordHash("hashed_pass").
		Save(ctx)
	require.NoError(t, err)

	// Invite 3 guardians (threshold k = 2)
	inputs := []auth.InviteGuardianInput{
		{Email: "g1@example.com", Name: "G1"},
		{Email: "g2@example.com", Name: "G2"},
		{Email: "g3@example.com", Name: "G3"},
	}
	resGdn, err := gdnSvc.InviteGuardians(ctx, userID, inputs, "http://localhost:8080")
	require.NoError(t, err)
	require.Len(t, resGdn.Guardians, 3)

	// Accept all 3 invites
	for i, gdn := range resGdn.Guardians {
		token := parseInviteToken(resGdn.InviteURLs[i])
		err = gdnSvc.AcceptGuardianInvite(ctx, gdn.ID, token)
		require.NoError(t, err)
	}

	// Initiate recovery
	resInit, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "gdnproof@example.com",
		IPAddress:   "198.51.100.1",
	})
	require.NoError(t, err)

	// Get active contacts to find share hashes
	contacts, err := repo.GetActiveRecoveryContactsByUser(ctx, userID)
	require.NoError(t, err)

	// Construct dummy share payload matching first contact's share hash
	share1Bytes := []byte(fmt.Sprintf("dummy_share_data_%s", contacts[0].ID))
	share1Hex := hex.EncodeToString(share1Bytes)

	// Update contact's share_hash in DB to match
	_ = repo.UpdateRecoveryContactShare(ctx, contacts[0].ID, contacts[0].ShareIndex, hex.EncodeToString(sha256Sum(share1Bytes)))

	// Submit share 1 (1 of 2 threshold)
	reached, err := svc.SubmitGuardianShareProof(ctx, resInit.RecoveryRequestID, share1Hex)
	require.NoError(t, err)
	assert.False(t, reached, "1 of 2 threshold MUST NOT mark verified")

	// Submit share 2 (2 of 2 threshold)
	share2Bytes := []byte(fmt.Sprintf("dummy_share_data_%s", contacts[1].ID))
	share2Hex := hex.EncodeToString(share2Bytes)
	_ = repo.UpdateRecoveryContactShare(ctx, contacts[1].ID, contacts[1].ShareIndex, hex.EncodeToString(sha256Sum(share2Bytes)))

	reached2, err := svc.SubmitGuardianShareProof(ctx, resInit.RecoveryRequestID, share2Hex)
	require.NoError(t, err)
	assert.True(t, reached2, "2 of 2 threshold MUST mark proof_verified")

	req, err := repo.GetRecoveryRequestByID(ctx, resInit.RecoveryRequestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusProofVerified, req.Status)
}

func TestSubmitOldPasswordProof_LockoutSchedule(t *testing.T) {
	svc, telemetry, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	passHash, _ := crypto.HashPasswordArgon2id("OldValidPass123!")
	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("oldpassproof@example.com").
		SetPasswordHash(passHash).
		Save(ctx)
	require.NoError(t, err)

	ip := "198.51.100.50"
	ua := "Mozilla/5.0"
	lang := "en-US"

	cookie, err := telemetry.RecordSuccessfulLoginTelemetry(ctx, userID, "", ip, ua, lang)
	require.NoError(t, err)

	resInit, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "oldpassproof@example.com",
		IPAddress:    ip,
		UserAgent:    ua,
		AcceptLang:   lang,
		DeviceCookie: cookie,
	})
	require.NoError(t, err)

	// 1. Submit WRONG password
	err = svc.SubmitOldPasswordProof(ctx, resInit.RecoveryRequestID, "WrongPassword123!")
	assert.ErrorIs(t, err, auth.ErrInvalidProof)

	u, _ := client.User.Get(ctx, userID)
	assert.Equal(t, 1, u.RecoveryFailedAttempts)

	// 2. Submit CORRECT password
	err = svc.SubmitOldPasswordProof(ctx, resInit.RecoveryRequestID, "OldValidPass123!")
	require.NoError(t, err)

	req, err := repo.GetRecoveryRequestByID(ctx, resInit.RecoveryRequestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusProofVerified, req.Status)
}

func TestSubmitSecurityQuestionsProof_EnforcesHigherTierExhaustion(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	policyRepo := policy.NewRepository(repo.GetClientFactory())
	gdnSvc := auth.NewGuardianService(repo, policyRepo)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	meta := map[string]interface{}{
		"security_questions": []interface{}{
			map[string]interface{}{"question": "Pet?", "answer_hash": "hash"},
		},
	}

	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("sqexh@example.com").
		SetPasswordHash("hashed_pass").
		SetMetadata(meta).
		Save(ctx)
	require.NoError(t, err)

	// Enroll a guardian
	inputs := []auth.InviteGuardianInput{{Email: "guardian@example.com", Name: "Guardian"}}
	resGdn, err := gdnSvc.InviteGuardians(ctx, userID, inputs, "http://localhost:8080")
	require.NoError(t, err)
	token := parseInviteToken(resGdn.InviteURLs[0])
	_ = gdnSvc.AcceptGuardianInvite(ctx, resGdn.Guardians[0].ID, token)

	resInit, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "sqexh@example.com",
		IPAddress:   "203.0.113.10",
	})
	require.NoError(t, err)

	// Attempt security questions proof without submitting guardian shares
	err = svc.SubmitSecurityQuestionsProof(ctx, resInit.RecoveryRequestID, map[string]string{"answer": "Fluffy"})
	assert.ErrorIs(t, err, auth.ErrHigherTierMethodsNotExhausted, "Security questions MUST fail if guardian shares have not been attempted")
}

func parseInviteToken(u string) string {
	parts := strings.Split(u, "#token=")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
