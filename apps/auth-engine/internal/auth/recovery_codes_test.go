/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_codes_test.go
 * Tier: Internal Feature Package / Integration Tests
 *
 * Description: End-to-end integration tests for 16-batch single-use backup recovery codes:
 *              - Automatic generation on first 2FA TOTP confirmation
 *              - Argon2id one-way password hashing (RFC 9106 t=3, m=64MB, p=4)
 *              - 2FA challenge login bypassing TOTP via single-use recovery code
 *              - Rejection of used codes with explicit "already used" error
 *              - Status endpoint tracking remaining count without exposing code values
 *              - Password step-up regeneration invalidating all previous code batches
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryCodes_FullLifecycle_E2E(t *testing.T) {
	cfg := &config.EnvConfig{
		AuthnAPIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		AuthnEncryptionKey: "super_secret_32_byte_kms_encryption_key_authn_2026!",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_rec_lifecycle_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	polRepo := policy.NewRepository(factory)
	svc := auth.NewService(repo, cfg, nil)
	handler := auth.NewHandler(svc, polRepo, nil)

	app := fiber.New()
	handler.RegisterRoutes(app, nil)

	password := "RecoverySecret123!"

	// 1. Signup
	signUpPayload := map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "recoveryuser@example.com",
		"password":    password,
		"name":        "Recovery User",
	}
	sBytes, _ := json.Marshal(signUpPayload)
	reqSignUp := httptest.NewRequest("POST", "/v1/client/signup", bytes.NewReader(sBytes))
	reqSignUp.Header.Set("Content-Type", "application/json")
	respSignUp, err := app.Test(reqSignUp, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, respSignUp.StatusCode)

	var authResp auth.AuthResponse
	_ = json.NewDecoder(respSignUp.Body).Decode(&authResp)
	token := authResp.AccessToken
	require.NotEmpty(t, token)

	// 2. Enroll TOTP
	reqEnroll := httptest.NewRequest("POST", "/v1/client/2fa/totp/enroll", nil)
	reqEnroll.Header.Set("Authorization", "Bearer "+token)
	respEnroll, err := app.Test(reqEnroll, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respEnroll.StatusCode)

	var enrollJSON struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	_ = json.NewDecoder(respEnroll.Body).Decode(&enrollJSON)
	require.NotEmpty(t, enrollJSON.Secret)

	// 3. Confirm TOTP -> Triggers auto-generation of 16 recovery codes
	totpCode, err := totp.GenerateCode(enrollJSON.Secret, time.Now())
	require.NoError(t, err)

	cBytes, _ := json.Marshal(map[string]string{"code": totpCode})
	reqConfirm := httptest.NewRequest("POST", "/v1/client/2fa/totp/confirm", bytes.NewReader(cBytes))
	reqConfirm.Header.Set("Authorization", "Bearer "+token)
	reqConfirm.Header.Set("Content-Type", "application/json")
	respConfirm, err := app.Test(reqConfirm, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respConfirm.StatusCode)

	var confirmResp auth.ConfirmTOTPResult
	_ = json.NewDecoder(respConfirm.Body).Decode(&confirmResp)
	assert.True(t, confirmResp.RecoveryCodesCreated)
	assert.Len(t, confirmResp.RecoveryCodes, 16)

	initialCodes := confirmResp.RecoveryCodes
	codeToUse := initialCodes[0]
	unusedOldCode := initialCodes[1]

	// 4. Check initial recovery codes status -> remaining 16
	reqStatus1 := httptest.NewRequest("GET", "/v1/client/2fa/recovery-codes/status", nil)
	reqStatus1.Header.Set("Authorization", "Bearer "+token)
	respStatus1, err := app.Test(reqStatus1, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respStatus1.StatusCode)

	var status1 auth.RecoveryCodesStatusResult
	_ = json.NewDecoder(respStatus1.Body).Decode(&status1)
	assert.Equal(t, 16, status1.RemainingCount)
	assert.Equal(t, 16, status1.TotalCount)
	assert.True(t, status1.HasRecoveryCodes)

	// 5. Login to trigger 2FA challenge (mfa_token)
	lBytes, _ := json.Marshal(map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "recoveryuser@example.com",
		"password":    password,
	})
	reqLogin := httptest.NewRequest("POST", "/v1/client/login", bytes.NewReader(lBytes))
	reqLogin.Header.Set("Content-Type", "application/json")
	respLogin, err := app.Test(reqLogin, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respLogin.StatusCode)

	var loginResp auth.AuthResponse
	_ = json.NewDecoder(respLogin.Body).Decode(&loginResp)
	assert.True(t, loginResp.MFARequired)
	assert.NotEmpty(t, loginResp.MFAToken)

	// 6. Use ONE Recovery Code to complete login (bypassing TOTP)
	vBytes, _ := json.Marshal(map[string]string{
		"mfa_token": loginResp.MFAToken,
		"code":      codeToUse,
		"method":    "backup_code",
	})
	reqVerify := httptest.NewRequest("POST", "/v1/client/auth/2fa/verify", bytes.NewReader(vBytes))
	reqVerify.Header.Set("Content-Type", "application/json")
	respVerify, err := app.Test(reqVerify, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respVerify.StatusCode)

	var verifyResp auth.AuthResponse
	_ = json.NewDecoder(respVerify.Body).Decode(&verifyResp)
	assert.NotEmpty(t, verifyResp.AccessToken)

	// 7. Attempt to RE-USE the exact same consumed recovery code -> MUST fail with "already used" error
	lBytes2, _ := json.Marshal(map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "recoveryuser@example.com",
		"password":    password,
	})
	reqLogin2 := httptest.NewRequest("POST", "/v1/client/login", bytes.NewReader(lBytes2))
	reqLogin2.Header.Set("Content-Type", "application/json")
	respLogin2, err := app.Test(reqLogin2, 10000)
	require.NoError(t, err)

	var loginResp2 auth.AuthResponse
	_ = json.NewDecoder(respLogin2.Body).Decode(&loginResp2)

	vBytesReuse, _ := json.Marshal(map[string]string{
		"mfa_token": loginResp2.MFAToken,
		"code":      codeToUse,
		"method":    "backup_code",
	})
	reqVerifyReuse := httptest.NewRequest("POST", "/v1/client/auth/2fa/verify", bytes.NewReader(vBytesReuse))
	reqVerifyReuse.Header.Set("Content-Type", "application/json")
	respVerifyReuse, err := app.Test(reqVerifyReuse, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, respVerifyReuse.StatusCode)

	var errResp map[string]string
	_ = json.NewDecoder(respVerifyReuse.Body).Decode(&errResp)
	assert.Equal(t, "this recovery code has already been used", errResp["error"])

	// 8. Confirm remaining count decremented to 15
	reqStatus2 := httptest.NewRequest("GET", "/v1/client/2fa/recovery-codes/status", nil)
	reqStatus2.Header.Set("Authorization", "Bearer "+token)
	respStatus2, err := app.Test(reqStatus2, 10000)
	require.NoError(t, err)

	var status2 auth.RecoveryCodesStatusResult
	_ = json.NewDecoder(respStatus2.Body).Decode(&status2)
	assert.Equal(t, 15, status2.RemainingCount)

	// 9. Regenerate Recovery Codes via Password Step-Up
	rBytes, _ := json.Marshal(map[string]string{"password": password})
	reqRegen := httptest.NewRequest("POST", "/v1/client/2fa/recovery-codes/regenerate", bytes.NewReader(rBytes))
	reqRegen.Header.Set("Authorization", "Bearer "+token)
	reqRegen.Header.Set("Content-Type", "application/json")
	respRegen, err := app.Test(reqRegen, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respRegen.StatusCode)

	var regenResp struct {
		Message       string   `json:"message"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.NewDecoder(respRegen.Body).Decode(&regenResp)
	assert.Len(t, regenResp.RecoveryCodes, 16)

	// 10. Confirm status is back to 16
	reqStatus3 := httptest.NewRequest("GET", "/v1/client/2fa/recovery-codes/status", nil)
	reqStatus3.Header.Set("Authorization", "Bearer "+token)
	respStatus3, err := app.Test(reqStatus3, 10000)
	require.NoError(t, err)

	var status3 auth.RecoveryCodesStatusResult
	_ = json.NewDecoder(respStatus3.Body).Decode(&status3)
	assert.Equal(t, 16, status3.RemainingCount)

	// 11. Confirm ALL old codes (including previously unused `unusedOldCode`) are now invalid
	lBytes3, _ := json.Marshal(map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "recoveryuser@example.com",
		"password":    password,
	})
	reqLogin3 := httptest.NewRequest("POST", "/v1/client/login", bytes.NewReader(lBytes3))
	reqLogin3.Header.Set("Content-Type", "application/json")
	respLogin3, err := app.Test(reqLogin3, 10000)
	require.NoError(t, err)

	var loginResp3 auth.AuthResponse
	_ = json.NewDecoder(respLogin3.Body).Decode(&loginResp3)

	vBytesOld, _ := json.Marshal(map[string]string{
		"mfa_token": loginResp3.MFAToken,
		"code":      unusedOldCode,
		"method":    "backup_code",
	})
	reqVerifyOld := httptest.NewRequest("POST", "/v1/client/auth/2fa/verify", bytes.NewReader(vBytesOld))
	reqVerifyOld.Header.Set("Content-Type", "application/json")
	respVerifyOld, err := app.Test(reqVerifyOld, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, respVerifyOld.StatusCode)

	var errRespOld map[string]string
	_ = json.NewDecoder(respVerifyOld.Body).Decode(&errRespOld)
	assert.Equal(t, "invalid recovery code", errRespOld["error"])
}
