/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/verify_refresh_token/main.go
 * Tier: System Verification Script / Refresh Token & Rotation Test
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"

	"github.com/gofiber/fiber/v2"
)

const (
	publishableKey = "pk_test_demo12345678901234567890123456789012"
	testEmail      = "refresh_verify_user@example.com"
	testPassword   = "SuperSecret123!"
	serverPort     = 8099
	serverURL      = "http://localhost:8099"
)

func main() {
	log.Println("🚀 Initializing test Auth Engine server for Refresh Token & Grace Window verification...")

	cfg := &config.Config{
		Port:              serverPort,
		Env:               "test",
		DatabaseURL:       "file:mem_refresh_verify?mode=memory&cache=shared&_fk=1",
		EncryptionKey:     "super_secret_32_byte_kms_encryption_key_authn_2026!",
		APIKeyPepper:      "super_secret_32_byte_api_key_pepper_authn_2026!",
		JWTSigningKeyPath: "./keys/rsa_private.pem",
		EmailDriver:       "noop",
		RateLimitEnabled:  false,
	}

	factory, err := clientfactory.NewClientFactory("sqlite3", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("❌ Failed initializing database factory: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeyService := apikey.NewService(apiKeyRepo, cfg.APIKeyPepper)
	pkMiddleware := middleware.RequirePublishableKey(apiKeyService)

	policyRepo := policy.NewRepository(factory)
	emailProvider := email.NewNoopProvider()

	authRepo := auth.NewRepository(factory)
	authService := auth.NewService(authRepo, cfg, emailProvider)
	authHandler := auth.NewHandler(authService, policyRepo, nil)

	oauthRepo := oauth.NewRepository()
	oauthService := oauth.NewService(oauthRepo, authRepo, authService, cfg)
	oauthHandler := oauth.NewHandler(oauthService)

	authHandler.RegisterRoutes(app, pkMiddleware)
	oauthHandler.RegisterRoutes(app, pkMiddleware)

	ctx := privacy.NewBypassContext(context.Background())
	_ = authRepo.EnsureTenantExists(ctx, "tnt_default")
	_ = authRepo.EnsureDefaultApplicationExists(ctx, "app_test123", "tnt_default", []string{"http://localhost:3000/callback"})
	_ = apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_test_demo123", "app_test123", publishableKey, cfg.APIKeyPepper)

	go func() {
		if err := app.Listen(fmt.Sprintf(":%d", serverPort)); err != nil {
			log.Fatalf("❌ Server error: %v", err)
		}
	}()

	time.Sleep(300 * time.Millisecond)

	log.Println("✅ Server running on", serverURL)

	// Step 0: Signup test user
	signupBody, _ := json.Marshal(map[string]string{
		"email":       testEmail,
		"password":    testPassword,
		"name":        "Refresh Verify User",
		"tenant_id":   "tnt_default",
		"environment": "test",
	})

	req, _ := http.NewRequest("POST", serverURL+"/v1/client/signup", bytes.NewBuffer(signupBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 400 && resp.StatusCode != 409) {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Signup failed: status=%d, body=%s, err=%v", resp.StatusCode, string(body), err)
	}

	// -----------------------------------------------------------------------
	// Step 1: Login to get session & cookie (Web Client Path)
	// -----------------------------------------------------------------------
	log.Println("\n--- STEP 1: Login & Cookie Extraction ---")
	loginBody, _ := json.Marshal(map[string]string{
		"email":       testEmail,
		"password":    testPassword,
		"tenant_id":   "tnt_default",
		"environment": "test",
	})

	req, _ = http.NewRequest("POST", serverURL+"/v1/client/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		log.Fatalf("❌ Step 1 Login failed: status=%d, err=%v", resp.StatusCode, err)
	}

	var loginRes map[string]interface{}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(bodyBytes, &loginRes)

	var initialRefreshTokenCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authn_refresh_token" {
			initialRefreshTokenCookie = c
			break
		}
	}

	if initialRefreshTokenCookie == nil {
		log.Fatalf("❌ Step 1 Failed: authn_refresh_token cookie was NOT set on login response!")
	}
	initialRawToken := initialRefreshTokenCookie.Value
	log.Printf("✔ Step 1 Success: Login successful. Initial Refresh Token cookie: %s...", initialRawToken[:16])

	// -----------------------------------------------------------------------
	// Step 2: Call /v1/oauth/token with grant_type=refresh_token using Cookie
	// -----------------------------------------------------------------------
	log.Println("\n--- STEP 2: Refresh Token via Cookie ---")
	refreshBody, _ := json.Marshal(map[string]string{
		"grant_type": "refresh_token",
	})

	req, _ = http.NewRequest("POST", serverURL+"/v1/oauth/token", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)
	req.AddCookie(initialRefreshTokenCookie)

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Step 2 Refresh failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var refreshRes map[string]interface{}
	bodyBytes, _ = io.ReadAll(resp.Body)
	_ = json.Unmarshal(bodyBytes, &refreshRes)

	var rotatedRefreshTokenCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authn_refresh_token" {
			rotatedRefreshTokenCookie = c
			break
		}
	}

	if rotatedRefreshTokenCookie == nil {
		log.Fatalf("❌ Step 2 Failed: Rotated refresh cookie was NOT set!")
	}

	rotatedRawToken := rotatedRefreshTokenCookie.Value
	if rotatedRawToken == initialRawToken {
		log.Fatalf("❌ Step 2 Failed: Refresh token was NOT rotated! Old and new tokens are identical.")
	}

	newAccessToken := refreshRes["access_token"].(string)
	log.Printf("✔ Step 2 Success: Token refreshed via cookie! New Access Token issued (%s...). Rotated Refresh Token: %s...", newAccessToken[:20], rotatedRawToken[:16])

	// -----------------------------------------------------------------------
	// Step 3: Test 10-Second Grace Window & Past-Grace Window Theft Detection
	// -----------------------------------------------------------------------
	log.Println("\n--- STEP 3A: Immediate Reuse within 10s Grace Window ---")
	// Immediate re-use of OLD token (within 10s grace window)
	req, _ = http.NewRequest("POST", serverURL+"/v1/oauth/token", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)
	req.AddCookie(initialRefreshTokenCookie) // Old token

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Step 3A Grace window test failed! status=%d, body=%s", resp.StatusCode, string(body))
	}
	log.Printf("✔ Step 3A Success: In-flight reuse within grace window succeeded (Status 200 OK)!")

	log.Println("\n--- STEP 3B: Reuse past 10s Grace Window (Theft Detection) ---")
	log.Println("  Waiting 11 seconds for grace window to expire...")
	time.Sleep(11 * time.Second)

	req, _ = http.NewRequest("POST", serverURL+"/v1/oauth/token", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)
	req.AddCookie(initialRefreshTokenCookie) // Old token past grace window

	resp, err = client.Do(req)
	if resp.StatusCode != 401 {
		log.Fatalf("❌ Step 3B Theft detection failed! Expected 401 Unauthorized, got status=%d", resp.StatusCode)
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
	log.Printf("✔ Step 3B Success: Re-use past 10s grace window rejected with 401 Unauthorized! Response: %s", string(bodyBytes))

	// Verify that all user sessions were revoked due to theft detection
	log.Println("  Verifying active rotated token is also now revoked due to theft detection...")
	req, _ = http.NewRequest("POST", serverURL+"/v1/oauth/token", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)
	req.AddCookie(rotatedRefreshTokenCookie)

	resp, err = client.Do(req)
	if resp.StatusCode != 401 {
		log.Fatalf("❌ Step 3B Revocation check failed! Active session was not revoked upon theft detection!")
	}
	log.Printf("✔ Step 3B Success: All sessions for user were revoked upon theft detection!")

	// -----------------------------------------------------------------------
	// Step 4: Test Native / Mobile JSON Body Path
	// -----------------------------------------------------------------------
	log.Println("\n--- STEP 4: Native / Mobile JSON Body Path ---")
	// Re-login to get fresh session
	resp, _ = client.Do(req)
	req, _ = http.NewRequest("POST", serverURL+"/v1/client/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)
	req.Header.Set("X-Authn-Client-Type", "native")
	resp, _ = client.Do(req)
	bodyBytes, _ = io.ReadAll(resp.Body)
	var login2Res map[string]interface{}
	_ = json.Unmarshal(bodyBytes, &login2Res)
	nativeRawRefreshToken := login2Res["refresh_token"].(string)

	nativeRefreshBody, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": nativeRawRefreshToken,
	})

	req, _ = http.NewRequest("POST", serverURL+"/v1/oauth/token", bytes.NewBuffer(nativeRefreshBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Step 4 Native refresh failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	bodyBytes, _ = io.ReadAll(resp.Body)
	var nativeRefreshRes map[string]interface{}
	_ = json.Unmarshal(bodyBytes, &nativeRefreshRes)

	if nativeRefreshRes["access_token"] == nil || nativeRefreshRes["refresh_token"] == nil {
		log.Fatalf("❌ Step 4 Native refresh failed: response missing access_token or refresh_token!")
	}

	log.Printf("✔ Step 4 Success: Native JSON body path returned access_token and rotated refresh_token (%s...) in JSON response!", nativeRefreshRes["refresh_token"].(string)[:16])

	// -----------------------------------------------------------------------
	// Step 5: Test Garbage / Invalid Refresh Token
	// -----------------------------------------------------------------------
	log.Println("\n--- STEP 5: Garbage Refresh Token Rejection ---")
	garbageBody, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "garbage_invalid_token_123456789",
	})

	req, _ = http.NewRequest("POST", serverURL+"/v1/oauth/token", bytes.NewBuffer(garbageBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err = client.Do(req)
	if resp.StatusCode != 401 {
		log.Fatalf("❌ Step 5 Garbage token test failed! Expected 401 Unauthorized, got status=%d", resp.StatusCode)
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
	log.Printf("✔ Step 5 Success: Garbage refresh token rejected with 401 Unauthorized! Response: %s", string(bodyBytes))

	log.Println("\n🎉 ALL REFRESH TOKEN & ROTATION VERIFICATION TESTS PASSED CLEANLY!")
	_ = app.Shutdown()
}
