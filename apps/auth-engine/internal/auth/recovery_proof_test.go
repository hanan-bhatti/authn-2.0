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
	"net/url"
	"strings"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupGuardianProofUser enrols three guardians on a fresh account, accepts every invitation with
// the share its own link carried, initiates a recovery, and returns the request ID alongside the
// guardians' shares in enrollment order.
func setupGuardianProofUser(t *testing.T, svc *auth.RecoveryService, repo *auth.Repository, tenantID, email string) (string, []string) {
	t.Helper()
	ctx := testCtx()
	policyRepo := policy.NewRepository(repo.GetClientFactory())
	gdnSvc := auth.NewGuardianService(repo, policyRepo)

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")
	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail(email).
		SetPasswordHash("hashed_pass").
		Save(ctx)
	require.NoError(t, err)

	// Three guardians, so the threshold is 2 and a single approval is provably not enough.
	resGdn, err := gdnSvc.InviteGuardians(ctx, userID, []auth.InviteGuardianInput{
		{Email: "g1@example.com", Name: "G1"},
		{Email: "g2@example.com", Name: "G2"},
		{Email: "g3@example.com", Name: "G3"},
	}, "http://localhost:8080")
	require.NoError(t, err)
	require.Len(t, resGdn.Invites, 3)

	shares := make([]string, 0, len(resGdn.Invites))
	for _, invite := range resGdn.Invites {
		token, share := parseInviteLink(t, invite.URL)
		require.NoError(t, gdnSvc.AcceptGuardianInvite(ctx, invite.ContactID, token, share))
		shares = append(shares, share)
	}

	resInit, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       email,
		IPAddress:   "198.51.100.1",
	})
	require.NoError(t, err)

	return resInit.RecoveryRequestID, shares
}

func TestSubmitGuardianProof_ShareAccumulation(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	requestID, shares := setupGuardianProofUser(t, svc, repo, tenantID, "gdnproof@example.com")

	// Submit share 1 (1 of 2 threshold)
	reached, err := svc.SubmitGuardianShareProof(ctx, requestID, shares[0])
	require.NoError(t, err)
	assert.False(t, reached, "1 of 2 threshold MUST NOT mark verified")

	// Submit share 2 (2 of 2 threshold)
	reached2, err := svc.SubmitGuardianShareProof(ctx, requestID, shares[1])
	require.NoError(t, err)
	assert.True(t, reached2, "2 of 2 threshold MUST mark proof_verified")

	req, err := repo.GetRecoveryRequestByID(ctx, requestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusProofVerified, req.Status)
	assert.Len(t, req.SubmittedShareIndexes, 2, "each approving guardian is recorded once")
	assert.Equal(t, 2, req.SubmittedSharesCount)
}

// The threshold counts guardians, not submissions. Replaying one guardian's share must not carry a
// 2-of-3 request over the line, or a single guardian — or anyone who stole one share — recovers the
// account alone.
func TestSubmitGuardianProof_RejectsReplayOfTheSameShare(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	requestID, shares := setupGuardianProofUser(t, svc, repo, tenantID, "gdnreplay@example.com")

	reached, err := svc.SubmitGuardianShareProof(ctx, requestID, shares[0])
	require.NoError(t, err)
	require.False(t, reached)

	reached2, err := svc.SubmitGuardianShareProof(ctx, requestID, shares[0])
	assert.ErrorIs(t, err, auth.ErrShareAlreadySubmitted)
	assert.False(t, reached2)

	req, err := repo.GetRecoveryRequestByID(ctx, requestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusInitiated, req.Status, "a replay must not verify the request")
	assert.Equal(t, 1, req.SubmittedSharesCount, "a replay must not raise the count")

	// A second, different guardian still completes it.
	reached3, err := svc.SubmitGuardianShareProof(ctx, requestID, shares[2])
	require.NoError(t, err)
	assert.True(t, reached3)
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
	token, share := parseInviteLink(t, resGdn.Invites[0].URL)
	require.NoError(t, gdnSvc.AcceptGuardianInvite(ctx, resGdn.Invites[0].ContactID, token, share))

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

// parseInviteLink splits an invitation URL's fragment into the guardian's two secrets.
//
// Reading them out of the link rather than reaching into the database is deliberate: the link is the
// only copy of the share that exists, so a test that plants its own hash would pass even if the
// engine never handed the guardian anything.
func parseInviteLink(t *testing.T, u string) (token, share string) {
	t.Helper()
	_, fragment, found := strings.Cut(u, "#")
	require.True(t, found, "invitation link must carry a fragment: %s", u)

	values, err := url.ParseQuery(fragment)
	require.NoError(t, err)

	token = values.Get("token")
	share = values.Get("share")
	require.NotEmpty(t, token, "invitation link must carry a token")
	require.NotEmpty(t, share, "invitation link must carry a share")
	return token, share
}
