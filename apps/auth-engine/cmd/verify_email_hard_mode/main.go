/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/verify_email_hard_mode/main.go
 * Tier: Automated Verification Script / Hard Mode Email Verification Test
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"

	"github.com/gofiber/fiber/v2"
)

const (
	publishableKey = "pk_test_demo12345678901234567890123456789012"
	testEmail      = "hard_mode_user@example.com"
	testPassword   = "SuperSecret123!"
	serverPort     = 8098
	serverURL      = "http://localhost:8098"
)

func main() {
	log.Println("🚀 Initializing test Auth Engine server for Hard Mode Email Verification test...")

	cfg := &config.Config{
		Port:              serverPort,
		Env:               "test",
		DatabaseURL:       "file:mem_hard_verify?mode=memory&cache=shared&_fk=1",
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

	authHandler.RegisterRoutes(app, pkMiddleware)

	ctx := privacy.NewBypassContext(context.Background())
	_ = authRepo.EnsureTenantExists(ctx, "tnt_default")
	_ = authRepo.EnsureDefaultApplicationExists(ctx, "app_test123", "tnt_default", []string{"http://localhost:3000/callback"})
	_ = apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_test_demo123", "app_test123", publishableKey, cfg.APIKeyPepper)

	// Configure Hard Mode Email Verification for tenant tnt_default
	hardModePolicy := policy.SecurityPolicy{
		RequireEmailVerification: true,
		EmailVerificationMode:    "hard",
	}
	if _, err := policyRepo.UpdateSecurityPolicy(ctx, "tnt_default", hardModePolicy); err != nil {
		log.Fatalf("❌ Failed setting hard mode security policy: %v", err)
	}
	log.Println("🔒 Configured tenant tnt_default security policy: RequireEmailVerification=true, EmailVerificationMode=hard")

	go func() {
		if err := app.Listen(fmt.Sprintf(":%d", serverPort)); err != nil {
			log.Fatalf("❌ Server error: %v", err)
		}
	}()

	time.Sleep(300 * time.Millisecond)

	client := &http.Client{}

	// 1. Sign up new unverified user
	log.Println("\n--- STEP 1: Signup with Hard Mode Email Verification Enabled ---")
	signupBody, _ := json.Marshal(map[string]string{
		"email":       testEmail,
		"password":    testPassword,
		"name":        "Hard Mode User",
		"tenant_id":   "tnt_default",
		"environment": "test",
	})

	req, _ := http.NewRequest("POST", serverURL+"/v1/client/signup", bytes.NewBuffer(signupBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Signup failed: status=%d, body=%s", resp.StatusCode, string(body))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var signupRes map[string]interface{}
	_ = json.Unmarshal(bodyBytes, &signupRes)

	policyWarning, _ := signupRes["policy_warning"].(map[string]interface{})
	if policyWarning == nil || policyWarning["requires_email_verification"] != true {
		log.Fatalf("❌ Signup failed: policy_warning.requires_email_verification was NOT true in signup response! Response: %s", string(bodyBytes))
	}
	log.Printf("✔ Step 1 Success: Signup returned 201 Created with policy_warning.requires_email_verification = true!")

	// 2. Attempt login before email verification -> Expect 403 Forbidden
	log.Println("\n--- STEP 2: Login Attempt before Email Verification ---")
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
	if resp.StatusCode != 403 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Step 2 Failed! Expected status 403 Forbidden, got %d, body: %s", resp.StatusCode, string(body))
	}

	bodyBytes, _ = io.ReadAll(resp.Body)
	log.Printf("✔ Step 2 Success: Login rejected with 403 Forbidden! Response: %s", string(bodyBytes))

	// 3. Directly verify email via database/token and re-attempt login
	log.Println("\n--- STEP 3: Verify Email & Re-attempt Login ---")
	u, err := authRepo.FindUserByEmail(ctx, "tnt_default", "test", testEmail)
	if err != nil || u == nil {
		log.Fatalf("❌ Failed finding user: %v", err)
	}

	// Update user email_verified = true
	dbClient := factory.GetClient(ctx, "tnt_default", "test")
	_, err = dbClient.User.UpdateOneID(u.ID).SetEmailVerified(true).Save(ctx)
	if err != nil {
		log.Fatalf("❌ Failed setting email_verified=true: %v", err)
	}
	log.Println("  Updated user account: email_verified = true")

	// Attempt login again
	req, _ = http.NewRequest("POST", serverURL+"/v1/client/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Step 3 Login after verification failed! status=%d, body=%s", resp.StatusCode, string(body))
	}

	bodyBytes, _ = io.ReadAll(resp.Body)
	log.Printf("✔ Step 3 Success: Login succeeded after email verification with 200 OK! Response payload: %s", string(bodyBytes[:120])+"...")

	log.Println("\n🎉 HARD MODE EMAIL VERIFICATION TEST PASSED CLEANLY!")
	_ = app.Shutdown()
}
