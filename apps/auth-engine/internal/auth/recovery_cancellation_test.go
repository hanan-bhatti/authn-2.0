/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_cancellation_test.go
 * Tier: Internal Feature Package / Security Cancellation & Blacklist Tests
 *
 * Description: End-to-end security integration test simulating an attack scenario:
 *              1. Attacker initiates account recovery from hostile IP/subnet.
 *              2. Legitimate user detects alert and cancels via authenticated session OR signed link token.
 *              3. System transitions request to CANCELLED, blacklists attacker IP/subnet/fingerprint for 7 days,
 *                 flags account for security review, and revokes sessions.
 *              4. Subsequent recovery initiation from blacklisted attacker origin is BLOCKED with 403 / ErrOriginBlacklisted.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryCancellation_AttackerScenario_AuthenticatedSessionCancel(t *testing.T) {
	kmsKey := "super_secret_kms_key_32bytes_authn!"
	dbName := fmt.Sprintf("file:ent_cancel_auth_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)
	policyRepo := policy.NewRepository(factory)
	telemetry := auth.NewTelemetryService(repo, kmsKey, policyRepo)
	svc := auth.NewRecoveryService(repo, telemetry, policyRepo)
	ctx := testCtx()

	tenantID := "tnt_cancel_test"
	err = repo.EnsureTenantExists(ctx, tenantID)
	require.NoError(t, err)

	client := factory.GetClient(ctx, tenantID, "test")

	// 1. Create legitimate user with 2 active sessions
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err = client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("victim@example.com").
		SetEmailVerified(true).
		SetPasswordHash("valid_pass_hash").
		Save(ctx)
	require.NoError(t, err)

	sess1, err := client.Session.Create().
		SetID("sess_legit_active").
		SetUserID(userID).
		SetRefreshTokenHash("hash1").
		SetExpiresAt(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	sess2, err := client.Session.Create().
		SetID("sess_secondary").
		SetUserID(userID).
		SetRefreshTokenHash("hash2").
		SetExpiresAt(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	// 2. Attacker initiates recovery from hostile IP 198.51.100.44
	attackerIP := "198.51.100.44"
	attackerUA := "Mozilla/5.0 (EvilOS; AttackerBrowser/1.0)"

	initRes, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "victim@example.com",
		IPAddress:    attackerIP,
		UserAgent:    attackerUA,
		AcceptLang:   "en-US",
		DeviceCookie: "",
	})
	require.NoError(t, err)
	assert.Equal(t, "initiated", initRes.Status)
	assert.NotEmpty(t, initRes.CancellationToken)

	// Verify request in DB
	reqDb, err := repo.GetRecoveryRequestByID(ctx, initRes.RecoveryRequestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusInitiated, reqDb.Status)

	// 3. Legitimate user detects security alert and cancels from sess1
	err = svc.CancelRecoveryRequestByAuthenticatedSession(ctx, userID, initRes.RecoveryRequestID, sess1.ID)
	require.NoError(t, err)

	// 4. Verify post-cancellation security invariants:
	// a) Recovery request status is CANCELLED
	cancelledReq, err := repo.GetRecoveryRequestByID(ctx, initRes.RecoveryRequestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusCancelled, cancelledReq.Status)
	assert.NotNil(t, cancelledReq.CancelledAt)

	// b) User account is flagged for mandatory security review
	updatedUser, err := client.User.Get(ctx, userID)
	require.NoError(t, err)
	assert.True(t, updatedUser.SecurityReviewRequired, "User MUST be flagged for security review after recovery cancellation")

	// c) Sess1 (cancelling session) remains ACTIVE, while Sess2 is REVOKED
	s1, _ := client.Session.Get(ctx, sess1.ID)
	assert.Equal(t, session.StatusActive, s1.Status, "Cancelling session must remain active")

	s2, _ := client.Session.Get(ctx, sess2.ID)
	assert.Equal(t, session.StatusRevoked, s2.Status, "Secondary sessions must be revoked")

	// d) Subsequent recovery initiation attempt from attacker IP/subnet is BLOCKED
	_, err = svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "victim@example.com",
		IPAddress:    attackerIP,
		UserAgent:    attackerUA,
		AcceptLang:   "en-US",
		DeviceCookie: "",
	})
	assert.ErrorIs(t, err, auth.ErrOriginBlacklisted, "Attacker attempt from blacklisted IP/subnet MUST be blocked")

	// e) Legitimate user attempting recovery from clean IP is NOT blacklisted
	cleanIP := "203.0.113.88"
	cleanUA := "Mozilla/5.0 (Macintosh; Safari/17.0)"
	initLegitRes, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  "test",
		Email:        "victim@example.com",
		IPAddress:    cleanIP,
		UserAgent:    cleanUA,
		AcceptLang:   "en-US",
		DeviceCookie: "",
	})
	require.NoError(t, err, "Clean origin must not be impacted by attacker's blacklist entry")
	assert.Equal(t, "initiated", initLegitRes.Status)
}

func TestRecoveryCancellation_AttackerScenario_SignedTokenCancel(t *testing.T) {
	kmsKey := "super_secret_kms_key_32bytes_authn!"
	dbName := fmt.Sprintf("file:ent_cancel_tok_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)
	policyRepo := policy.NewRepository(factory)
	telemetry := auth.NewTelemetryService(repo, kmsKey, policyRepo)
	svc := auth.NewRecoveryService(repo, telemetry, policyRepo)
	ctx := testCtx()

	tenantID := "tnt_cancel_token_test"
	err = repo.EnsureTenantExists(ctx, tenantID)
	require.NoError(t, err)

	client := factory.GetClient(ctx, tenantID, "test")

	// 1. Create legitimate user
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err = client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("victim2@example.com").
		SetEmailVerified(true).
		SetPasswordHash("valid_pass_hash").
		Save(ctx)
	require.NoError(t, err)

	sess, err := client.Session.Create().
		SetID("sess_victim_active").
		SetUserID(userID).
		SetRefreshTokenHash("hash_victim").
		SetExpiresAt(time.Now().Add(24 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	// 2. Attacker initiates recovery from hostile IP 198.51.100.99
	attackerIP := "198.51.100.99"
	attackerUA := "Mozilla/5.0 (Windows NT 10.0; EvilBot/2.0)"

	initRes, err := svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "victim2@example.com",
		IPAddress:   attackerIP,
		UserAgent:   attackerUA,
		AcceptLang:  "en-US",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, initRes.CancellationToken)

	// 3. Legitimate user receives security alert email containing cancellation_token and clicks link unauthenticated
	err = svc.CancelRecoveryRequestBySignedToken(ctx, initRes.CancellationToken)
	require.NoError(t, err)

	// 4. Verify post-cancellation security invariants:
	// a) Recovery request status is CANCELLED
	cancelledReq, err := repo.GetRecoveryRequestByID(ctx, initRes.RecoveryRequestID)
	require.NoError(t, err)
	assert.Equal(t, recoveryrequest.StatusCancelled, cancelledReq.Status)

	// b) All sessions for user revoked (since signed link was unauthenticated)
	revokedSess, _ := client.Session.Get(ctx, sess.ID)
	assert.Equal(t, session.StatusRevoked, revokedSess.Status)

	// c) User account flagged for security review
	u, _ := client.User.Get(ctx, userID)
	assert.True(t, u.SecurityReviewRequired)

	// d) Attacker attempt from blacklisted IP/subnet rejected
	_, err = svc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "victim2@example.com",
		IPAddress:   attackerIP,
		UserAgent:   attackerUA,
		AcceptLang:  "en-US",
	})
	assert.ErrorIs(t, err, auth.ErrOriginBlacklisted)
}
