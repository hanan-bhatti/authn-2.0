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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
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
	err = repo.EnsureTenantExists(context.Background(), tenantID)
	require.NoError(t, err)

	return svc, telemetry, repo, tenantID
}

func TestRecoveryInitiate_PriorityOrder(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := context.Background()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// Create user with verified phone & email
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
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
	ctx := context.Background()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
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
	ctx := context.Background()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// User with NO phone, NO email verified, BUT has security questions metadata
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	meta := map[string]interface{}{
		"security_questions": []interface{}{
			map[string]interface{}{"question": "First pet name?", "answer_hash": "hash123"},
		},
	}

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
}

func TestRecoveryInitiate_ZeroMethodsDeadEnd_Returns400(t *testing.T) {
	svc, _, repo, tenantID := setupTestRecoveryService(t)
	ctx := context.Background()

	client := repo.GetClientFactory().GetClient(ctx, tenantID, "test")

	// User with 0 methods (email unverified, no phone, no guardians, no security questions, unfamiliar device)
	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
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
	svc, _, _, tenantID := setupTestRecoveryService(t)
	ctx := context.Background()

	inputNonExistent := auth.InitiateRecoveryInput{
		TenantID:    tenantID,
		Environment: "test",
		Email:       "nonexistent_user_999@example.com",
		IPAddress:   "198.51.100.1",
		UserAgent:   "Mozilla/5.0",
	}

	start := time.Now()
	res, err := svc.InitiateRecovery(ctx, inputNonExistent)
	duration := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, "initiated", res.Status)
	assert.Equal(t, []string{"email_otp"}, res.AvailableMethods)
	assert.Less(t, duration, 200*time.Millisecond, "Timing-safe Argon2 dummy iteration MUST execute smoothly")
}
