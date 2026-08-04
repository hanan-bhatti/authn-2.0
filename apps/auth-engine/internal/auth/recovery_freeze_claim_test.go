/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_freeze_claim_test.go
 * Tier: Internal Feature Package / Sub-step 4c Integration Tests
 *
 * Description: Automated test suite for the 48-hour freeze state machine, background worker expiration job,
 *              claim token redemption, password reset, 2FA wiping, fresh recovery codes, and session revocation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryFreezeStateTransition(t *testing.T) {
	svc, telemetry, repo, tenantID := setupTestRecoveryService(t)
	ctx := context.Background()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	passHash, _ := crypto.HashPasswordArgon2id("OldPass123!")
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("freeze@example.com").
		SetPasswordHash(passHash).
		Save(ctx)
	require.NoError(t, err)

	ip := "198.51.100.1"
	ua := "Mozilla/5.0"
	lang := "en-US"
	cookie, _ := telemetry.RecordSuccessfulLoginTelemetry(ctx, userID, "", ip, ua, lang)

	resInit, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "freeze@example.com",
		IPAddress:    ip,
		UserAgent:    ua,
		AcceptLang:   lang,
		DeviceCookie: cookie,
	})
	require.NoError(t, err)

	// Verify old password proof
	err = svc.SubmitOldPasswordProof(ctx, resInit.RecoveryRequestID, "OldPass123!")
	require.NoError(t, err)

	// Activate 48-hour freeze
	freezeReq, err := svc.ActivateFreezeWindow(ctx, resInit.RecoveryRequestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusFreezeActive, freezeReq.Status)
	assert.NotNil(t, freezeReq.FreezeStartedAt)
	assert.True(t, freezeReq.FreezeExpiresAt.After(time.Now().Add(47*time.Hour)), "Freeze duration MUST be 48 hours")
}

func TestProcessExpiredFreezes_BackgroundWorker(t *testing.T) {
	svc, telemetry, repo, tenantID := setupTestRecoveryService(t)
	ctx := context.Background()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	passHash, _ := crypto.HashPasswordArgon2id("OldPass123!")
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("worker@example.com").
		SetPasswordHash(passHash).
		Save(ctx)
	require.NoError(t, err)

	ip := "198.51.100.2"
	ua := "Mozilla/5.0"
	lang := "en-US"
	cookie, _ := telemetry.RecordSuccessfulLoginTelemetry(ctx, userID, "", ip, ua, lang)

	resInit, _ := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "worker@example.com",
		IPAddress:    ip,
		UserAgent:    ua,
		AcceptLang:   lang,
		DeviceCookie: cookie,
	})

	_ = svc.SubmitOldPasswordProof(ctx, resInit.RecoveryRequestID, "OldPass123!")
	freezeReq, _ := svc.ActivateFreezeWindow(ctx, resInit.RecoveryRequestID)

	// Simulate freeze expiry by updating freeze_expires_at to past
	pastTime := time.Now().Add(-1 * time.Hour)
	_ = client.RecoveryRequest.UpdateOne(freezeReq).
		SetFreezeExpiresAt(pastTime).
		Exec(ctx)

	// Execute background worker
	processed, err := svc.ProcessExpiredFreezes(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, processed, "Background worker MUST transition 1 expired freeze request")

	updated, err := repo.GetRecoveryRequestByID(ctx, freezeReq.ID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusReadyForClaim, updated.Status)
	assert.NotEmpty(t, updated.ClaimTokenHash)
}

func TestClaimAccount_FullExecution(t *testing.T) {
	svc, telemetry, repo, tenantID := setupTestRecoveryService(t)
	ctx := context.Background()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	passHash, _ := crypto.HashPasswordArgon2id("OldPass123!")
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	u, err := client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("claim@example.com").
		SetPasswordHash(passHash).
		Save(ctx)
	require.NoError(t, err)

	// Create an active session
	_ = client.Session.Create().
		SetID("sess_active123").
		SetUserID(u.ID).
		SetRefreshTokenHash("dummy_hash").
		SetExpiresAt(time.Now().Add(24 * time.Hour)).
		Exec(ctx)

	ip := "198.51.100.3"
	ua := "Mozilla/5.0"
	lang := "en-US"
	cookie, _ := telemetry.RecordSuccessfulLoginTelemetry(ctx, userID, "", ip, ua, lang)

	resInit, _ := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "claim@example.com",
		IPAddress:    ip,
		UserAgent:    ua,
		AcceptLang:   lang,
		DeviceCookie: cookie,
	})

	_ = svc.SubmitOldPasswordProof(ctx, resInit.RecoveryRequestID, "OldPass123!")
	freezeReq, _ := svc.ActivateFreezeWindow(ctx, resInit.RecoveryRequestID)

	// Set freeze expired
	_ = client.RecoveryRequest.UpdateOne(freezeReq).
		SetFreezeExpiresAt(time.Now().Add(-1 * time.Hour)).
		Exec(ctx)

	_, _ = svc.ProcessExpiredFreezes(ctx)

	// Manually set known claim token for redemption
	rawClaimToken := "claim_token_super_secret_123456"
	hashSum := sha256.Sum256([]byte(rawClaimToken))
	claimHash := hex.EncodeToString(hashSum[:])

	_ = client.RecoveryRequest.UpdateOne(freezeReq).
		SetClaimTokenHash(claimHash).
		SetClaimTokenExpiresAt(time.Now().Add(15 * time.Minute)).
		Exec(ctx)

	// Execute ClaimAccount
	claimRes, err := svc.ClaimAccount(ctx, auth.ClaimAccountInput{
		RequestID:   freezeReq.ID,
		ClaimToken:  rawClaimToken,
		NewPassword: "BrandNewSecurePassword123!",
		IPAddress:   ip,
		UserAgent:   ua,
		AcceptLang:  lang,
	})

	require.NoError(t, err)
	assert.Equal(t, "completed", claimRes.Status)
	assert.Len(t, claimRes.RecoveryCodes, 8, "8 fresh recovery codes MUST be issued")
	assert.NotEmpty(t, claimRes.DeviceCookie)

	// Verify new password
	updatedUser, _ := client.User.Get(ctx, u.ID)
	assert.True(t, crypto.VerifyPasswordArgon2id("BrandNewSecurePassword123!", updatedUser.PasswordHash))

	// Verify sessions revoked
	sessionsCount, _ := client.Session.Query().Where(session.UserID(u.ID)).Count(ctx)
	assert.Equal(t, 0, sessionsCount, "All prior active sessions MUST be deleted/revoked")

	// Verify RecoveryRequest status COMPLETED
	finalReq, _ := repo.GetRecoveryRequestByID(ctx, freezeReq.ID)
	assert.Equal(t, recoveryrequest.StatusCompleted, finalReq.Status)
}
