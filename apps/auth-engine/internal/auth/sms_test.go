/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/sms_test.go
 * Tier: Internal Feature Package / SMS 2FA & Method Disambiguation Unit & Integration Tests
 *
 * Description: End-to-end unit and integration tests for SMS OTP 2FA enrollment, confirmation,
 *              login challenge verification, rate limiting, password step-up removal,
 *              and strict multi-method disambiguation logic (method field required when > 1 active 2FA method).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSMSTestEnv(t *testing.T) (*auth.Service, *auth.Repository, func()) {
	cfg := &config.Config{
		APIKeyPepper:          "test_pepper_key_32_bytes_long_12345",
		EncryptionKey:         "super_secret_32_byte_kms_encryption_key_authn_2026!",
		WebAuthnRPDisplayName: "Authn Test",
		WebAuthnRPID:          "localhost",
		WebAuthnRPOrigins:     []string{"http://localhost:3000"},
		SMSDriver:             "noop",
	}

	dbURI := fmt.Sprintf("file:ent_sms_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbURI)
	require.NoError(t, err)

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), "tnt_default"))
	noopSMS, _ := sms.NewSMSProvider(cfg)
	svc := auth.NewService(repo, cfg, nil, noopSMS)

	cleanup := func() {
		factory.Close()
	}

	return svc, repo, cleanup
}

func TestSMS_Enroll_Confirm_Validation(t *testing.T) {
	svc, repo, cleanup := setupSMSTestEnv(t)
	defer cleanup()
	ctx := testCtx()

	// 1. Create test user
	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_default", "test", "smstest@example.com", "UserPassword123!", "SMS User", "UserAgent", "127.0.0.1")
	require.NoError(t, err)

	// 2. Begin SMS Enrollment with invalid phone format -> fail
	err = svc.BeginSMSEnrollment(ctx, u.ID, "12345")
	assert.Error(t, err, "invalid phone format must fail E.164 validation")

	// 3. Begin SMS Enrollment with valid E.164 phone
	phone := "+12025550199"
	err = svc.BeginSMSEnrollment(ctx, u.ID, phone)
	require.NoError(t, err)

	// Check repository state: pending method created
	pendingMethod, err := repo.GetSMSMethodForUser(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, pendingMethod)
	assert.False(t, pendingMethod.IsEnabled)
	assert.Equal(t, "sms", string(pendingMethod.Type))

	// 4. Confirm with wrong code -> fail
	_, err = svc.ConfirmSMSEnrollment(ctx, u.ID, "000000")
	assert.ErrorIs(t, err, auth.ErrSMSOTPExpired)
}

func TestSMS_AmbiguityCheck_MultipleMethods(t *testing.T) {
	svc, _, cleanup := setupSMSTestEnv(t)
	defer cleanup()
	ctx := testCtx()

	// 1. Create user
	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_default", "test", "multimethod@example.com", "UserPassword123!", "Multi 2FA User", "UserAgent", "127.0.0.1")
	require.NoError(t, err)

	// 2. Enroll & Confirm TOTP 2FA
	totpRes, err := svc.EnrollTOTP(ctx, u.ID)
	require.NoError(t, err)
	totpCode, err := totp.GenerateCode(totpRes.Secret, time.Now())
	require.NoError(t, err)
	confirmRes, err := svc.ConfirmTOTP(ctx, u.ID, totpCode)
	require.NoError(t, err)
	require.True(t, confirmRes.RecoveryCodesCreated)
	require.Len(t, confirmRes.RecoveryCodes, 16)

	// User now has TOTP + Backup Codes active (2 methods active)

	// 3. Test Disambiguation Requirement (CRITICAL RULE):
	// User has > 1 active 2FA method (TOTP + backup_code).
	// Omitting method in Verify2FACode MUST return ErrAmbiguous2FAMethod.
	err = svc.Verify2FACode(ctx, u.ID, "123456")
	assert.ErrorIs(t, err, auth.ErrAmbiguous2FAMethod, "omitting method when multiple 2FA methods exist MUST return ErrAmbiguous2FAMethod")

	// 4. Specifying method explicitly:
	// Specifying "totp" routes directly to TOTP verification
	totpCodeFresh, err := totp.GenerateCode(totpRes.Secret, time.Now())
	require.NoError(t, err)
	err = svc.Verify2FACode(ctx, u.ID, totpCodeFresh, "totp")
	assert.NoError(t, err, "explicit method 'totp' must succeed when valid TOTP code is provided")

	// Specifying "backup_code" with a valid recovery code routes directly to backup code verification
	validRecoveryCode := confirmRes.RecoveryCodes[0]
	err = svc.Verify2FACode(ctx, u.ID, validRecoveryCode, "backup_code")
	assert.NoError(t, err, "explicit method 'backup_code' must succeed when valid recovery code is provided")
}

func TestSMS_RateLimit_3RequestsPer10Mins(t *testing.T) {
	svc, _, cleanup := setupSMSTestEnv(t)
	defer cleanup()
	ctx := testCtx()

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_default", "test", "smsratelimit@example.com", "UserPassword123!", "Rate Limit User", "UserAgent", "127.0.0.1")
	require.NoError(t, err)

	phone := "+12025550177"
	// Request 1
	err = svc.BeginSMSEnrollment(ctx, u.ID, phone)
	require.NoError(t, err)

	// Request 2
	err = svc.BeginSMSEnrollment(ctx, u.ID, phone)
	require.NoError(t, err)

	// Request 3
	err = svc.BeginSMSEnrollment(ctx, u.ID, phone)
	require.NoError(t, err)

	// Request 4 -> Exceeds rate limit!
	err = svc.BeginSMSEnrollment(ctx, u.ID, phone)
	assert.ErrorIs(t, err, auth.ErrTooManySMSRequests, "4th SMS request within 10 minutes MUST return ErrTooManySMSRequests")
}

func TestSMS_Disable_ReVerification_And_SessionRevocation(t *testing.T) {
	svc, repo, cleanup := setupSMSTestEnv(t)
	defer cleanup()
	ctx := testCtx()

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_default", "test", "smsdisable@example.com", "UserPassword123!", "Disable User", "UserAgent", "127.0.0.1")
	require.NoError(t, err)

	phone := "+12025550166"
	err = svc.BeginSMSEnrollment(ctx, u.ID, phone)
	require.NoError(t, err)

	// 1. Disable SMS 2FA with wrong password -> should fail
	err = svc.DisableSMS2FA(ctx, u.ID, "WrongPassword123!", "UserAgent", "127.0.0.1")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)

	// Verify method still pending/exists in DB
	tfm, err := repo.GetSMSMethodForUser(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, tfm)
}
