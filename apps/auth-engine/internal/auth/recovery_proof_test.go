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

	entries, ids := enrolledSecurityQuestions(t, [][2]string{
		{"First pet name?", "Fluffy"},
		{"City you were born in?", "Lahore"},
		{"Mother's maiden name?", "Khan"},
	})
	meta := map[string]interface{}{"security_questions": entries}

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

	// The answers submitted here are the correct ones. The tier gate is checked ahead of any
	// verification, so knowing every answer still does not skip the guardian step.
	err = svc.SubmitSecurityQuestionsProof(ctx, resInit.RecoveryRequestID, map[string]string{
		ids[0]: "Fluffy",
		ids[1]: "Lahore",
		ids[2]: "Khan",
	})
	assert.ErrorIs(t, err, auth.ErrHigherTierMethodsNotExhausted, "Security questions MUST fail if guardian shares have not been attempted")
}

// setupSecurityQuestionsOnlyUser creates an account whose only recovery method is its
// security questions — no verified email, no phone, no guardians — and initiates a
// recovery request against it, returning the request ID and the enrolled question IDs.
//
// The proof route refuses while a higher tier is unexhausted, so a bare account is what
// lets these tests reach the verification itself rather than the gate in front of it.
func setupSecurityQuestionsOnlyUser(t *testing.T, svc *auth.RecoveryService, repo *auth.Repository, tenantID, email string, priorFailures int) (string, []string) {
	t.Helper()
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")
	entries, ids := enrolledSecurityQuestions(t, [][2]string{
		{"First pet name?", "Fluffy"},
		{"City you were born in?", "Lahore"},
		{"Mother's maiden name?", "Khan"},
	})

	_, err := client.User.Create().
		SetID(idgen.New("usr")).
		SetTenantID(tenantID).
		SetEmail(email).
		SetEmailVerified(false).
		SetPasswordHash("hashed_pass").
		SetRecoveryFailedAttempts(priorFailures).
		SetMetadata(map[string]interface{}{"security_questions": entries}).
		Save(ctx)
	require.NoError(t, err)

	res, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       email,
		IPAddress:   "203.0.113.77",
		UserAgent:   "Mozilla/5.0",
	})
	require.NoError(t, err)
	require.Equal(t, []string{"security_questions"}, res.AvailableMethods)

	return res.RecoveryRequestID, ids
}

func TestSubmitSecurityQuestionsProof_EveryAnswerCorrect(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	requestID, ids := setupSecurityQuestionsOnlyUser(t, svc, repo, tenantID, "sqpass@example.com", 2)

	// Typed the way the same person types months later on another keyboard: different case,
	// stray outer spaces, a doubled space inside. The engine folds all three before hashing,
	// so a correct answer is not rejected for how it was typed.
	err := svc.SubmitSecurityQuestionsProof(ctx, requestID, map[string]string{
		ids[0]: "  fluffy ",
		ids[1]: "LAHORE",
		ids[2]: "Khan",
	})
	require.NoError(t, err)

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")
	req, err := repo.GetRecoveryRequestByID(ctx, requestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusProofVerified, req.Status)
	// The column is optional, so it arrives as a pointer: nil means nothing recorded which
	// method got the request through, and the audit trail for a recovery depends on it.
	require.NotNil(t, req.ProofMethodUsed)
	assert.Equal(t, recoveryrequest.ProofMethodUsedSecurityQuestions, *req.ProofMethodUsed)

	u, err := client.User.Get(ctx, req.UserID)
	require.NoError(t, err)
	assert.Equal(t, 0, u.RecoveryFailedAttempts, "a verified proof MUST clear earlier failures rather than carry escalated lockout steps forward")
	assert.Nil(t, u.RecoveryLockoutUntil)
}

func TestSubmitSecurityQuestionsProof_OneWrongAnswerFailsTheSet(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	requestID, ids := setupSecurityQuestionsOnlyUser(t, svc, repo, tenantID, "sqwrong@example.com", 0)

	// Two of three right. The answers are low-entropy and correlated — whoever knows a
	// birthplace often knows a maiden name — so accepting a subset would cost an attacker
	// far less than the fraction suggests.
	err := svc.SubmitSecurityQuestionsProof(ctx, requestID, map[string]string{
		ids[0]: "Fluffy",
		ids[1]: "Lahore",
		ids[2]: "Not the maiden name",
	})
	assert.ErrorIs(t, err, auth.ErrInvalidProof)

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")
	req, err := repo.GetRecoveryRequestByID(ctx, requestID)
	require.NoError(t, err)
	assert.NotEqual(t, recoveryrequest.StatusProofVerified, req.Status, "a partial set MUST NOT advance the request")

	u, err := client.User.Get(ctx, req.UserID)
	require.NoError(t, err)
	assert.Equal(t, 1, u.RecoveryFailedAttempts, "a wrong answer MUST count against the recovery lockout schedule")
}

func TestSubmitSecurityQuestionsProof_OmittedAnswerFailsTheSet(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	requestID, ids := setupSecurityQuestionsOnlyUser(t, svc, repo, tenantID, "sqmissing@example.com", 0)

	// The third ID is absent rather than wrong. Sending only what you know must not be a way
	// to shrink the set you have to know.
	err := svc.SubmitSecurityQuestionsProof(ctx, requestID, map[string]string{
		ids[0]: "Fluffy",
		ids[1]: "Lahore",
	})
	assert.ErrorIs(t, err, auth.ErrInvalidProof)

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")
	req, err := repo.GetRecoveryRequestByID(ctx, requestID)
	require.NoError(t, err)
	assert.NotEqual(t, recoveryrequest.StatusProofVerified, req.Status)

	u, err := client.User.Get(ctx, req.UserID)
	require.NoError(t, err)
	assert.Equal(t, 1, u.RecoveryFailedAttempts)
}

func TestSubmitSecurityQuestionsProof_EmptyAnswerMapIsRefused(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	requestID, _ := setupSecurityQuestionsOnlyUser(t, svc, repo, tenantID, "sqempty@example.com", 0)

	// The route once accepted any non-empty map without checking a single answer, which made
	// the sole recovery method on a bare account a free takeover.
	err := svc.SubmitSecurityQuestionsProof(ctx, requestID, map[string]string{})
	assert.ErrorIs(t, err, auth.ErrInvalidProof)

	err = svc.SubmitSecurityQuestionsProof(ctx, requestID, map[string]string{"answer": "Fluffy"})
	assert.ErrorIs(t, err, auth.ErrInvalidProof, "answers keyed by anything other than a question ID MUST NOT verify")

	req, err := repo.GetRecoveryRequestByID(ctx, requestID)
	require.NoError(t, err)
	assert.NotEqual(t, recoveryrequest.StatusProofVerified, req.Status)
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
