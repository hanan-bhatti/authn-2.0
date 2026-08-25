/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_initiate_test.go
 * Tier: Internal Feature Package / Sub-step 4a Integration Tests
 *
 * Description: Test suite for recovery initiation, dynamic method resolution priority order,
 *              trusted device old-password unlocking, security questions fallback, zero-methods 400 error,
 *              and timing-safe email enumeration protection.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRecoveryService(t *testing.T) (*auth.RecoveryService, *auth.TelemetryService, *auth.Repository, string) {
	kmsKey := "super_secret_kms_key_32bytes_authn!"
	dbName := fmt.Sprintf("file:ent_rec_init_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)
	policyRepo := policy.NewRepository(factory)
	telemetry := auth.NewTelemetryService(repo, kmsKey, policyRepo)
	svc := auth.NewRecoveryService(repo, telemetry, policyRepo)

	tenantID := "tnt_test_rec"
	err = repo.EnsureTenantExists(testCtx(), tenantID)
	require.NoError(t, err)

	return svc, telemetry, repo, tenantID
}

// enrolledSecurityQuestions builds the metadata value the engine stores for an
// enrolled roster — one entry per pair, each carrying its own ID and an Argon2id
// digest of its answer — and returns the IDs in the same order, since a proof is
// keyed by ID rather than by position.
//
// The folding rule is spelled out here rather than borrowed, because the engine's
// copy is unexported. The duplication is the point: if the engine's rule changes and
// this does not, every stored answer stops matching and these tests say so instead
// of quietly agreeing with whatever the engine now does.
func enrolledSecurityQuestions(t *testing.T, pairs [][2]string) ([]interface{}, []string) {
	t.Helper()

	entries := make([]interface{}, 0, len(pairs))
	ids := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		hash, err := crypto.HashPasswordArgon2id(strings.ToLower(strings.Join(strings.Fields(pair[1]), " ")))
		require.NoError(t, err)

		id := idgen.New("sq")
		ids = append(ids, id)
		entries = append(entries, map[string]interface{}{
			"id":          id,
			"question":    pair[0],
			"answer_hash": hash,
		})
	}
	return entries, ids
}

func TestRecoveryInitiate_PriorityOrder(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// Create user with verified phone & email
	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("priority@example.com").
		SetEmailVerified(true).
		SetPhoneNumber("+12025550199").
		SetPhoneVerified(true).
		SetPasswordHash("hashed_pass").
		Save(ctx)
	require.NoError(t, err)

	// Initiate recovery from unfamiliar device/network
	input := auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "priority@example.com",
		IPAddress:   "198.51.100.15",
		UserAgent:   "Mozilla/5.0",
	}

	res, err := svc.InitiateRecovery(ctx, input)
	require.NoError(t, err)
	assert.Equal(t, "initiated", res.Status)
	assert.False(t, res.IsTrustedDeviceOrigin)
	assert.Equal(t, []string{"phone_otp", "email_otp"}, res.AvailableMethods)
}

func TestRecoveryInitiate_OldPasswordUnlockedOnTrust(t *testing.T) {
	svc, telemetry, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("trusted@example.com").
		SetEmailVerified(true).
		SetPasswordHash("hashed_pass").
		Save(ctx)
	require.NoError(t, err)

	ip := "198.51.100.20"
	ua := "Mozilla/5.0 (macOS)"
	lang := "en-US"

	// 1. Record successful login to register device token and IP subnet
	cookie, err := telemetry.RecordSuccessfulLoginTelemetry(ctx, userID, "", ip, ua, lang)
	require.NoError(t, err)

	// 2. Initiate recovery from SAME trusted device + subnet
	input := auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "trusted@example.com",
		IPAddress:    ip,
		UserAgent:    ua,
		AcceptLang:   lang,
		DeviceCookie: cookie,
	}

	res, err := svc.InitiateRecovery(ctx, input)
	require.NoError(t, err)
	assert.True(t, res.IsTrustedDeviceOrigin)
	assert.Contains(t, res.AvailableMethods, "old_password", "old_password MUST be unlocked on trusted device + familiar subnet")
}

func TestRecoveryInitiate_SecurityQuestionsFallback(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// User with NO phone, NO email verified, BUT has security questions metadata
	userID := idgen.New("usr")
	entries, ids := enrolledSecurityQuestions(t, [][2]string{
		{"First pet name?", "Fluffy"},
		{"City you were born in?", "Lahore"},
		{"Mother's maiden name?", "Khan"},
	})
	meta := map[string]interface{}{"security_questions": entries}

	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("sq@example.com").
		SetEmailVerified(false).
		SetPasswordHash("hashed_pass").
		SetMetadata(meta).
		Save(ctx)
	require.NoError(t, err)

	input := auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "sq@example.com",
		IPAddress:   "203.0.113.1",
		UserAgent:   "Mozilla/5.0",
	}

	res, err := svc.InitiateRecovery(ctx, input)
	require.NoError(t, err)
	assert.Equal(t, []string{"security_questions"}, res.AvailableMethods, "security_questions MUST surface as sole fallback when higher-tier methods are empty")

	// The prompts travel with the offer. A locked-out caller has no session and no other
	// route to them, so a method offered without its questions is unattemptable.
	require.Len(t, res.SecurityQuestions, 3, "the offer MUST carry every enrolled prompt")
	for i, q := range res.SecurityQuestions {
		assert.Equal(t, ids[i], q.ID, "prompt IDs MUST match the stored roster, since a proof is keyed by ID")
		assert.NotEmpty(t, q.Question)
	}
	assert.Equal(t, "First pet name?", res.SecurityQuestions[0].Question)

	// Nothing about the answers may ride along. The DTO has no digest field, so the check
	// is on the serialized form a client actually receives.
	encoded, err := json.Marshal(res.SecurityQuestions)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "$argon2", "answer digests MUST NOT reach the client")
	assert.NotContains(t, string(encoded), "answer", "no answer field of any kind may be serialized")
}

func TestRecoveryInitiate_SecurityQuestionWithoutAnswerHashIsNotAMethod(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// A roster entry carrying a prompt but no digest. There is nothing to verify an answer
	// against, so treating it as an enrolled question would offer a method that accepts
	// anything — which for the sole available method is an open door into the account.
	userID := idgen.New("usr")
	meta := map[string]interface{}{
		"security_questions": []interface{}{
			map[string]interface{}{"id": idgen.New("sq"), "question": "Half-written question?"},
		},
	}

	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("sqhalf@example.com").
		SetEmailVerified(false).
		SetPasswordHash("hashed_pass").
		SetMetadata(meta).
		Save(ctx)
	require.NoError(t, err)

	_, err = svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "sqhalf@example.com",
		IPAddress:   "203.0.113.2",
		UserAgent:   "Mozilla/5.0",
	})
	assert.ErrorIs(t, err, auth.ErrNoRecoveryMethodsAvailable, "an unverifiable entry MUST NOT count as an available method")
}

func TestRecoveryInitiate_ZeroMethodsDeadEnd_Returns400(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// User with 0 methods (email unverified, no phone, no guardians, no security questions, unfamiliar device)
	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("zeromethods@example.com").
		SetEmailVerified(false).
		SetPasswordHash("hashed_pass").
		Save(ctx)
	require.NoError(t, err)

	input := auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "zeromethods@example.com",
		IPAddress:   "203.0.113.99",
		UserAgent:   "Mozilla/5.0",
	}

	_, err = svc.InitiateRecovery(ctx, input)
	assert.ErrorIs(t, err, auth.ErrNoRecoveryMethodsAvailable, "Zero available methods MUST return ErrNoRecoveryMethodsAvailable")
}

func TestRecoveryInitiate_TimingSafeNonExistentUser(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := testCtx()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// A real, recoverable user to measure the genuine code path against.
	userID := idgen.New("usr")
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("realuser_timing@example.com").
		SetEmailVerified(true).
		SetPasswordHash("hashed_pass").
		Save(ctx)
	require.NoError(t, err)

	inputNonExistent := auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "nonexistent_user_999@example.com",
		IPAddress:   "198.51.100.1",
		UserAgent:   "Mozilla/5.0",
	}
	inputReal := auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "realuser_timing@example.com",
		IPAddress:   "198.51.100.2",
		UserAgent:   "Mozilla/5.0",
	}

	// The response itself must be indistinguishable from a real user's.
	res, err := svc.InitiateRecovery(ctx, inputNonExistent)
	require.NoError(t, err)
	assert.Equal(t, "initiated", res.Status)
	assert.Equal(t, []string{"email_otp"}, res.AvailableMethods)

	// So must the time it takes. Measure the median of both paths rather than
	// asserting an absolute wall-clock bound: the security property is that the
	// two are *comparable*, and an absolute ceiling only measures how loaded the
	// machine is — Argon2 is deliberately expensive, so a fixed 200ms limit
	// failed intermittently on a busy CI box while proving nothing about
	// enumeration resistance.
	median := func(input auth.InitiateRecoveryInput) time.Duration {
		const samples = 5
		durations := make([]time.Duration, 0, samples)
		for i := 0; i < samples; i++ {
			start := time.Now()
			_, err := svc.InitiateRecovery(ctx, input)
			require.NoError(t, err)
			durations = append(durations, time.Since(start))
		}
		sort.Slice(durations, func(a, b int) bool { return durations[a] < durations[b] })
		return durations[len(durations)/2]
	}

	realMedian := median(inputReal)
	fakeMedian := median(inputNonExistent)

	// Guard against the dummy path being skipped entirely (the actual
	// enumeration leak): it must not be dramatically faster than the real one.
	ratio := float64(fakeMedian) / float64(realMedian)
	assert.Greaterf(t, ratio, 0.25,
		"non-existent-user path (%v) is far faster than the real path (%v): the timing-safe Argon2 dummy iteration is not running, leaking account existence",
		fakeMedian, realMedian)
	assert.Lessf(t, ratio, 4.0,
		"non-existent-user path (%v) is far slower than the real path (%v), which also leaks account existence",
		fakeMedian, realMedian)
}
