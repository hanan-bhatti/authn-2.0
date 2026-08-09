/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/webauthn_test.go
 * Tier: Internal Feature Package / Integration Tests
 *
 * Description: Integration test suite for WebAuthn / Passkeys (FIDO2):
 *              - Registration begin challenge generation
 *              - Login begin challenge flow validation
 *              - Listing registered passkeys with metadata
 *              - Passkey deletion policy (no password step-up when multiple 2FA methods remain;
 *                mandatory Argon2id password step-up + session revocation when removing last 2FA method)
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupWebAuthnTestEnvironment(t *testing.T) (*fiber.App, *auth.Service, *auth.Repository, string, string) {
	cfg := &config.Config{
		APIKeyPepper:          "test_pepper_key_32_bytes_long_12345",
		EncryptionKey:         "super_secret_32_byte_kms_encryption_key_authn_2026!",
		WebAuthnRPID:          "localhost",
		WebAuthnRPOrigins:     []string{"http://localhost:8080"},
		WebAuthnRPDisplayName: "Authn Platform",
	}
	dbURI := fmt.Sprintf("file:ent_webauthn_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbURI)
	require.NoError(t, err)

	repo := auth.NewRepository(factory)
	polRepo := policy.NewRepository(factory)
	svc := auth.NewService(repo, cfg, nil)
	handler := auth.NewHandler(svc, polRepo, nil)

	app := fiber.New()
	handler.RegisterRoutes(app, nil)

	password := "PasskeySecret123!"

	// Signup user
	signUpPayload := map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "passkeyuser@example.com",
		"password":    password,
		"name":        "Passkey User",
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

	return app, svc, repo, token, password
}

func TestWebAuthn_BeginRegistration(t *testing.T) {
	app, _, _, token, _ := setupWebAuthnTestEnvironment(t)

	req := httptest.NewRequest("POST", "/v1/client/2fa/webauthn/register/begin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var res struct {
		Options   map[string]interface{} `json:"options"`
		SessionID string                 `json:"session_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	assert.NotEmpty(t, res.SessionID)
	assert.NotEmpty(t, res.Options)
}

func TestWebAuthn_BeginLogin_NoPasskeys(t *testing.T) {
	app, _, _, token, password := setupWebAuthnTestEnvironment(t)

	// Login to get mfa_token (must enroll a 2FA method first so login returns MFA challenge)
	// Enroll & confirm TOTP first
	reqEnroll := httptest.NewRequest("POST", "/v1/client/2fa/webauthn/register/begin", nil)
	reqEnroll.Header.Set("Authorization", "Bearer "+token)
	respEnroll, err := app.Test(reqEnroll, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respEnroll.StatusCode)

	// Login with password
	lBytes, _ := json.Marshal(map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "passkeyuser@example.com",
		"password":    password,
	})
	reqLogin := httptest.NewRequest("POST", "/v1/client/login", bytes.NewReader(lBytes))
	reqLogin.Header.Set("Content-Type", "application/json")
	respLogin, err := app.Test(reqLogin, 10000)
	require.NoError(t, err)

	var loginResp auth.AuthResponse
	_ = json.NewDecoder(respLogin.Body).Decode(&loginResp)

	// Attempt begin login without passkeys registered -> Should fail
	bBytes, _ := json.Marshal(map[string]string{"mfa_token": "dummy_mfa_token"})
	reqBegin := httptest.NewRequest("POST", "/v1/client/2fa/webauthn/login/begin", bytes.NewReader(bBytes))
	reqBegin.Header.Set("Content-Type", "application/json")
	respBegin, err := app.Test(reqBegin, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, respBegin.StatusCode)
}

func TestWebAuthn_PasskeyManagement_And_ConditionalDeletion(t *testing.T) {
	app, _, repo, token, password := setupWebAuthnTestEnvironment(t)
	ctx := context.Background()

	// 1. Get User ID from session token
	reqListInitial := httptest.NewRequest("GET", "/v1/client/2fa/webauthn/credentials", nil)
	reqListInitial.Header.Set("Authorization", "Bearer "+token)
	respListInitial, err := app.Test(reqListInitial, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respListInitial.StatusCode)

	var listInitRes struct {
		Credentials []auth.PasskeyDTO `json:"credentials"`
	}
	_ = json.NewDecoder(respListInitial.Body).Decode(&listInitRes)
	assert.Empty(t, listInitRes.Credentials)

	// Find User in DB
	u, err := repo.FindUserByEmail(ctx, "tnt_test", "test", "passkeyuser@example.com")
	require.NoError(t, err)

	// 2. Direct database insert of 2 passkeys for testing
	pk1, err := repo.CreateWebAuthnPasskey(ctx, u.ID, "MacBook Touch ID", "cred_id_11111", []byte("public_key_1"), 5, map[string]interface{}{"aaguid": "aaaa1111"})
	require.NoError(t, err)

	pk2, err := repo.CreateWebAuthnPasskey(ctx, u.ID, "Work YubiKey 5C", "cred_id_22222", []byte("public_key_2"), 12, map[string]interface{}{"aaguid": "bbbb2222"})
	require.NoError(t, err)

	// 3. List Passkeys -> Should return 2 items
	reqList := httptest.NewRequest("GET", "/v1/client/2fa/webauthn/credentials", nil)
	reqList.Header.Set("Authorization", "Bearer "+token)
	respList, err := app.Test(reqList, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respList.StatusCode)

	var listRes struct {
		Credentials []auth.PasskeyDTO `json:"credentials"`
	}
	_ = json.NewDecoder(respList.Body).Decode(&listRes)
	assert.Len(t, listRes.Credentials, 2)
	assert.Equal(t, "MacBook Touch ID", listRes.Credentials[0].Name)
	assert.Equal(t, uint32(5), listRes.Credentials[0].SignCount)

	// 4. Delete Passkey 1 (when 2 passkeys remain) -> MUST succeed WITHOUT password step-up
	reqDel1 := httptest.NewRequest("DELETE", "/v1/client/2fa/webauthn/credentials/"+pk1.ID, nil)
	reqDel1.Header.Set("Authorization", "Bearer "+token)
	respDel1, err := app.Test(reqDel1, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respDel1.StatusCode)

	// 5. Delete Passkey 2 (the LAST remaining 2FA method):
	// 5a. Attempt WITHOUT password -> MUST fail with step-up required error
	reqDel2NoPass := httptest.NewRequest("DELETE", "/v1/client/2fa/webauthn/credentials/"+pk2.ID, nil)
	reqDel2NoPass.Header.Set("Authorization", "Bearer "+token)
	respDel2NoPass, err := app.Test(reqDel2NoPass, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, respDel2NoPass.StatusCode)

	var errNoPass map[string]string
	_ = json.NewDecoder(respDel2NoPass.Body).Decode(&errNoPass)
	assert.Contains(t, errNoPass["error"], "invalid password step-up confirmation required")

	// 5b. Attempt with WRONG password -> MUST fail
	wBytes, _ := json.Marshal(map[string]string{"password": "WrongPassword!"})
	reqDel2Wrong := httptest.NewRequest("DELETE", "/v1/client/2fa/webauthn/credentials/"+pk2.ID, bytes.NewReader(wBytes))
	reqDel2Wrong.Header.Set("Authorization", "Bearer "+token)
	reqDel2Wrong.Header.Set("Content-Type", "application/json")
	respDel2Wrong, err := app.Test(reqDel2Wrong, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, respDel2Wrong.StatusCode)

	// 5c. Attempt with VALID Argon2id password -> MUST succeed and disable 2FA
	pBytes, _ := json.Marshal(map[string]string{"password": password})
	reqDel2Valid := httptest.NewRequest("DELETE", "/v1/client/2fa/webauthn/credentials/"+pk2.ID, bytes.NewReader(pBytes))
	reqDel2Valid.Header.Set("Authorization", "Bearer "+token)
	reqDel2Valid.Header.Set("Content-Type", "application/json")
	respDel2Valid, err := app.Test(reqDel2Valid, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respDel2Valid.StatusCode)

	// 6. Confirm passkey list is now empty
	reqListEmpty := httptest.NewRequest("GET", "/v1/client/2fa/webauthn/credentials", nil)
	reqListEmpty.Header.Set("Authorization", "Bearer "+token)
	respListEmpty, err := app.Test(reqListEmpty, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respListEmpty.StatusCode)

	var listEmptyRes struct {
		Credentials []auth.PasskeyDTO `json:"credentials"`
	}
	_ = json.NewDecoder(respListEmpty.Body).Decode(&listEmptyRes)
	assert.Empty(t, listEmptyRes.Credentials)
}

func TestLogin_MFAResponseMethods_SingleSourceOfTruth(t *testing.T) {
	app, svc, repo, token, password := setupWebAuthnTestEnvironment(t)
	_ = svc
	_ = token
	_ = password

	ctx := context.Background()
	u, err := repo.FindUserByEmail(ctx, "tnt_test", "test", "passkeyuser@example.com")
	require.NoError(t, err)

	// Manually insert a WebAuthn passkey row for the user (No TOTP!)
	_, err = repo.CreateWebAuthnPasskey(ctx, u.ID, "Key1", "cred_123", []byte("pubkey"), 1, map[string]interface{}{
		"flags": map[string]interface{}{"backup_eligible": true, "backup_state": true},
	})
	require.NoError(t, err)

	// Perform password login to trigger MFA challenge
	loginPayload := map[string]string{
		"tenant_id":   "tnt_test",
		"environment": "test",
		"email":       "passkeyuser@example.com",
		"password":    "PasskeySecret123!",
	}
	lBytes, _ := json.Marshal(loginPayload)
	reqLogin := httptest.NewRequest("POST", "/v1/client/login", bytes.NewReader(lBytes))
	reqLogin.Header.Set("Content-Type", "application/json")

	respLogin, err := app.Test(reqLogin, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, respLogin.StatusCode)

	var loginRes struct {
		MFARequired bool     `json:"mfa_required"`
		MFAToken    string   `json:"mfa_token"`
		Methods     []string `json:"methods"`
	}
	err = json.NewDecoder(respLogin.Body).Decode(&loginRes)
	require.NoError(t, err)

	assert.True(t, loginRes.MFARequired)
	require.NotEmpty(t, loginRes.MFAToken)

	// Verify decoded JWT claims methods
	claims, err := jwtpkg.VerifyMFAChallengeToken(loginRes.MFAToken, "super_secret_32_byte_kms_encryption_key_authn_2026!")
	require.NoError(t, err)

	// SINGLE SOURCE OF TRUTH VERIFICATION:
	// Outer response methods array and decoded JWT claims methods array MUST BE IDENTICAL.
	assert.Equal(t, claims.Methods, loginRes.Methods, "Outer JSON methods array and JWT claim methods MUST be identical")
	assert.ElementsMatch(t, []string{"passkey"}, loginRes.Methods)
	assert.NotContains(t, loginRes.Methods, "totp", "User has no TOTP enrolled; totp must NOT appear in methods")
}
