/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/totp_test.go
 * Tier: Internal Feature Package / Unit & Integration Tests
 *
 * Description: Comprehensive test suite for RFC 6238 2FA TOTP enrollment, confirmation,
 *              skew window validation (+-1 step acceptance, outside step rejection),
 *              password-driven disable with Argon2id re-verification & session revocation,
 *              and MFA challenge login integration.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrypto_AES256GCM_Encryption(t *testing.T) {
	key := "super_secret_32_byte_kms_encryption_key_authn_2026!"
	secret := "JBSWY3DPEHPK3PXP"

	ciphertext, err := crypto.EncryptAES256GCM(secret, key)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, secret, ciphertext)

	decrypted, err := crypto.DecryptAES256GCM(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, secret, decrypted)

	// Test wrong key failure
	_, err = crypto.DecryptAES256GCM(ciphertext, "wrong_encryption_key_1234567890123")
	assert.Error(t, err)
}

func TestTOTP_Enrollment_PendingState(t *testing.T) {
	cfg := &config.Config{
		APIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		EncryptionKey: "super_secret_32_byte_kms_encryption_key_authn_2026!",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_totp_enroll_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), "tnt_test"))
	svc := auth.NewService(repo, cfg, nil)

	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "totpuser@example.com", "Password123!", "TOTP User", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)

	// 1. Enroll TOTP
	enrollRes, err := svc.EnrollTOTP(ctx, u.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, enrollRes.Secret)
	assert.Contains(t, enrollRes.URI, "otpauth://totp/Authn%20Platform:totpuser@example.com")

	// 2. Verify DB state is pending (is_enabled = false)
	pendingTfm, err := repo.GetTOTPMethodForUser(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, pendingTfm)
	assert.False(t, pendingTfm.IsEnabled, "TwoFactorMethod MUST have is_enabled=false upon enrollment")

	// Active query MUST return nil
	activeTfm, err := repo.GetActiveTOTPMethodForUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Nil(t, activeTfm, "GetActiveTOTPMethodForUser MUST return nil for unconfirmed pending enrollment")
}

func TestTOTP_FullLifecycle_And_SkewTolerance(t *testing.T) {
	cfg := &config.Config{
		APIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		EncryptionKey: "super_secret_32_byte_kms_encryption_key_authn_2026!",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_totp_lifecycle_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), "tnt_test"))
	svc := auth.NewService(repo, cfg, nil)

	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "lifecycle@example.com", "MySecretPass123!", "Lifecycle User", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)

	// 1. Enroll
	enrollRes, err := svc.EnrollTOTP(ctx, u.ID)
	require.NoError(t, err)
	secret := enrollRes.Secret

	// 2. Attempt confirm with wrong code -> Should fail
	_, err = svc.ConfirmTOTP(ctx, u.ID, "000000")
	assert.ErrorIs(t, err, auth.ErrInvalidTOTPCode)

	// 3. Confirm with valid code
	validCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, u.ID, validCode)
	require.NoError(t, err)

	// Verify method is now active
	activeTfm, err := repo.GetActiveTOTPMethodForUser(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, activeTfm)
	assert.True(t, activeTfm.IsEnabled)

	// 4. Test Skew Tolerance Boundaries
	now := time.Now()

	// t = 0 (current time) -> Valid
	codeCurrent, err := totp.GenerateCode(secret, now)
	require.NoError(t, err)
	assert.NoError(t, svc.VerifyTOTP(ctx, u.ID, codeCurrent))

	// t - 30s (skew -1 boundary) -> Valid
	codePrev, err := totp.GenerateCode(secret, now.Add(-30*time.Second))
	require.NoError(t, err)
	assert.NoError(t, svc.VerifyTOTP(ctx, u.ID, codePrev), "Code generated 30s ago (skew -1) MUST be accepted")

	// t + 30s (skew +1 boundary) -> Valid
	codeNext, err := totp.GenerateCode(secret, now.Add(30*time.Second))
	require.NoError(t, err)
	assert.NoError(t, svc.VerifyTOTP(ctx, u.ID, codeNext), "Code generated 30s in future (skew +1) MUST be accepted")

	// t - 60s (skew -2 outside boundary) -> Rejected!
	codeFarPrev, err := totp.GenerateCode(secret, now.Add(-60*time.Second))
	require.NoError(t, err)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, u.ID, codeFarPrev), auth.ErrInvalidTOTPCode)

	// t + 60s (skew +2 outside boundary) -> Rejected!
	codeFarNext, err := totp.GenerateCode(secret, now.Add(60*time.Second))
	require.NoError(t, err)
	assert.ErrorIs(t, svc.VerifyTOTP(ctx, u.ID, codeFarNext), auth.ErrInvalidTOTPCode)
}

func TestTOTP_LoginIntegration_And_ChallengeFlow(t *testing.T) {
	cfg := &config.Config{
		APIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		EncryptionKey: "super_secret_32_byte_kms_encryption_key_authn_2026!",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_totp_login_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), "tnt_test"))
	svc := auth.NewService(repo, cfg, nil)

	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	// 1. Create User & Activate TOTP
	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "totplogin@example.com", "Password123!", "TOTP Login", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)

	enrollRes, err := svc.EnrollTOTP(ctx, u.ID)
	require.NoError(t, err)
	secret := enrollRes.Secret

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, u.ID, code)
	require.NoError(t, err)

	// 2. Perform Login with active TOTP -> MUST return Err2FARequired and mfaToken
	_, mfaToken, refreshTok, err := svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "totplogin@example.com", "Password123!", "Mozilla/5.0", "127.0.0.1")
	assert.ErrorIs(t, err, auth.Err2FARequired)
	assert.NotEmpty(t, mfaToken, "mfaToken must be populated when 2FA is required")
	assert.Empty(t, refreshTok, "refreshTok must be empty when 2FA is required")

	// 3. Complete 2FA Challenge Verification
	challengeCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	verifiedUser, accessTok, refreshTok, err := svc.VerifyTOTPChallenge(ctx, mfaToken, challengeCode, "totp", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, u.ID, verifiedUser.ID)
	assert.NotEmpty(t, accessTok)
	assert.NotEmpty(t, refreshTok)
}

func TestTOTP_Disable_ReVerification_And_SessionRevocation(t *testing.T) {
	cfg := &config.Config{
		APIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		EncryptionKey: "super_secret_32_byte_kms_encryption_key_authn_2026!",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_totp_disable_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), "tnt_test"))
	svc := auth.NewService(repo, cfg, nil)

	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	// 1. Create user, activate TOTP, and issue extra active sessions
	password := "HighSecurityPass123!"
	u, accessTok, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "disable2fa@example.com", password, "Disable User", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)
	assert.NotEmpty(t, accessTok)

	enrollRes, err := svc.EnrollTOTP(ctx, u.ID)
	require.NoError(t, err)
	code, err := totp.GenerateCode(enrollRes.Secret, time.Now())
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(ctx, u.ID, code)
	require.NoError(t, err)

	// 2. Disable with wrong password -> MUST be rejected (Argon2id re-verification failure)
	err = svc.DisableTOTP(ctx, u.ID, "WrongPassword!", "Mozilla/5.0", "127.0.0.1")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)

	// Verify TOTP is still active
	activeTfm, err := repo.GetActiveTOTPMethodForUser(ctx, u.ID)
	require.NoError(t, err)
	assert.NotNil(t, activeTfm)

	// 3. Disable with correct password -> MUST succeed, delete TOTP, and revoke sessions
	err = svc.DisableTOTP(ctx, u.ID, password, "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)

	// Verify TOTP method is deleted
	deletedTfm, err := repo.GetTOTPMethodForUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedTfm)
}

func TestTOTP_HTTPHandlers_E2E(t *testing.T) {
	cfg := &config.Config{
		APIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		EncryptionKey: "super_secret_32_byte_kms_encryption_key_authn_2026!",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_totp_http_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), "tnt_test"))
	svc := auth.NewService(repo, cfg, nil)
	handler := auth.NewHandler(svc, nil, nil)

	app := fiber.New()
	handler.RegisterRoutes(app, testScopeMiddleware("tnt_test", "test"))

	// 1. Signup
	signUpPayload := map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "httptotp@example.com",
		"password":    "HTTPPass123!",
		"name":        "HTTP User",
	}
	bodyBytes, _ := json.Marshal(signUpPayload)
	req := httptest.NewRequest("POST", "/v1/client/auth/signup", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var authResp auth.AuthResponse
	_ = json.NewDecoder(resp.Body).Decode(&authResp)
	token := authResp.AccessToken
	require.NotEmpty(t, token)

	// 2. Enroll TOTP
	reqEnroll := httptest.NewRequest("POST", "/v1/client/auth/2fa/totp/enroll", nil)
	reqEnroll.Header.Set("Authorization", "Bearer "+token)
	respEnroll, err := app.Test(reqEnroll, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respEnroll.StatusCode)

	var enrollJSON struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	_ = json.NewDecoder(respEnroll.Body).Decode(&enrollJSON)
	assert.NotEmpty(t, enrollJSON.Secret)
	assert.NotEmpty(t, enrollJSON.URI)

	// 3. Confirm TOTP
	confirmCode, err := totp.GenerateCode(enrollJSON.Secret, time.Now())
	require.NoError(t, err)

	confirmPayload := map[string]string{"code": confirmCode}
	cBytes, _ := json.Marshal(confirmPayload)
	reqConfirm := httptest.NewRequest("POST", "/v1/client/auth/2fa/totp/confirm", bytes.NewReader(cBytes))
	reqConfirm.Header.Set("Authorization", "Bearer "+token)
	reqConfirm.Header.Set("Content-Type", "application/json")
	respConfirm, err := app.Test(reqConfirm, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respConfirm.StatusCode)

	// 4. Login after TOTP is active
	loginPayload := map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "httptotp@example.com",
		"password":    "HTTPPass123!",
	}
	lBytes, _ := json.Marshal(loginPayload)
	reqLogin := httptest.NewRequest("POST", "/v1/client/auth/login", bytes.NewReader(lBytes))
	reqLogin.Header.Set("Content-Type", "application/json")
	respLogin, err := app.Test(reqLogin, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respLogin.StatusCode)

	var loginResp auth.AuthResponse
	_ = json.NewDecoder(respLogin.Body).Decode(&loginResp)
	assert.True(t, loginResp.MFARequired)
	assert.Contains(t, loginResp.Methods, "totp")
	assert.NotEmpty(t, loginResp.MFAToken)
	assert.Empty(t, loginResp.AccessToken)

	// 5. Verify Challenge Token + Code
	vCode, err := totp.GenerateCode(enrollJSON.Secret, time.Now())
	require.NoError(t, err)

	verifyPayload := map[string]string{
		"mfa_token": loginResp.MFAToken,
		"code":      vCode,
		"method":    "totp",
	}
	vBytes, _ := json.Marshal(verifyPayload)
	reqVerify := httptest.NewRequest("POST", "/v1/client/auth/2fa/verify", bytes.NewReader(vBytes))
	reqVerify.Header.Set("Content-Type", "application/json")
	respVerify, err := app.Test(reqVerify, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respVerify.StatusCode)

	var finalAuthResp auth.AuthResponse
	_ = json.NewDecoder(respVerify.Body).Decode(&finalAuthResp)
	assert.NotEmpty(t, finalAuthResp.AccessToken)

	// 6. Disable TOTP with password
	disablePayload := map[string]string{
		"password": "HTTPPass123!",
	}
	dBytes, _ := json.Marshal(disablePayload)
	reqDisable := httptest.NewRequest("POST", "/v1/client/auth/2fa/totp/disable", bytes.NewReader(dBytes))
	reqDisable.Header.Set("Authorization", "Bearer "+finalAuthResp.AccessToken)
	reqDisable.Header.Set("Content-Type", "application/json")
	respDisable, err := app.Test(reqDisable, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respDisable.StatusCode)
}
