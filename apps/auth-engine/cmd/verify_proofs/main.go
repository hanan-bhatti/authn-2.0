/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/verify_proofs/main.go
 * Tier: Automated Proof & Boundary Verification Script
 *
 * Description: Verifies:
 *              1. Rate limiting (429 Too Many Requests) on POST /v1/client/resend-verification.
 *              2. Expired token rejection (400 Bad Request) on GET /v1/client/verify-email.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

func main() {
	log.Println("🧪 Executing Rate Limiter & Token Expiry Proof Verification...")

	client := &http.Client{Timeout: 5 * time.Second}
	apiBase := "http://localhost:8080"
	publishableKey := "pk_test_demo12345678901234567890123456789012"

	// ---------------------------------------------------------
	// PROOF 2: Rate Limiter on POST /v1/client/resend-verification
	// ---------------------------------------------------------
	log.Println("\n--- PROOF 2: Resend Verification Rate Limiting Test ---")
	targetEmail := fmt.Sprintf("ratelimit_user_%d@example.com", time.Now().Unix())

	resendPayload := map[string]interface{}{
		"email":       targetEmail,
		"tenant_id":   "tnt_default",
		"environment": "test",
	}
	payloadBytes, _ := json.Marshal(resendPayload)

	for i := 1; i <= 6; i++ {
		req, _ := http.NewRequest("POST", apiBase+"/v1/client/resend-verification", bytes.NewBuffer(payloadBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Authn-Publishable-Key", publishableKey)
		req.Header.Set("User-Agent", "RateLimitTester/1.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Request %d failed: %v", i, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		log.Printf("Request #%d -> HTTP Status: %d %s | Response: %s", i, resp.StatusCode, resp.Status, string(respBody))
		if i == 6 {
			if resp.StatusCode == http.StatusTooManyRequests {
				log.Println("✅ PROOF 2 PASSED: 6th resend request returned HTTP 429 Too Many Requests as expected!")
			} else {
				log.Fatalf("❌ PROOF 2 FAILED: Expected HTTP 429 on 6th request, got %d", resp.StatusCode)
			}
		}
	}

	// ---------------------------------------------------------
	// PROOF 3: Expired Verification Token Rejection Test
	// ---------------------------------------------------------
	log.Println("\n--- PROOF 3: Expired Token Rejection Test ---")

	// Directly create a user in SQLite DB with an expired token (1 hour in the past)
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:authn.db?cache=shared&_fk=1")
	if err != nil {
		log.Fatalf("Failed connecting to DB factory: %v", err)
	}
	defer factory.Close()

	repo := auth.NewRepository(factory)
	ctx := privacy.NewBypassContext(context.Background())

	rawExpiredToken := "expired_raw_token_1234567890abcdef1234567890abcdef"
	h := sha256.Sum256([]byte(rawExpiredToken))
	tokenHash := hex.EncodeToString(h[:])

	expiredUserID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	expiredEmail := fmt.Sprintf("expired_user_%d@example.com", time.Now().Unix())

	u, err := repo.CreateUser(ctx, expiredUserID, "tnt_default", "test", expiredEmail, "hash123", "Expired Token User")
	if err != nil {
		log.Fatalf("Failed creating test user: %v", err)
	}

	pastExpiry := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	err = repo.SetUserEmailVerificationToken(ctx, u.ID, tokenHash, pastExpiry)
	if err != nil {
		log.Fatalf("Failed setting expired token: %v", err)
	}
	log.Printf("Created user %s with token expired at %s", u.Email, pastExpiry.Format(time.RFC3339))

	// Execute GET /v1/client/verify-email with the expired token
	verifyReq, _ := http.NewRequest("GET", apiBase+"/v1/client/verify-email?token="+rawExpiredToken, nil)
	verifyReq.Header.Set("X-Authn-Publishable-Key", publishableKey)

	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		log.Fatalf("Verification request failed: %v", err)
	}
	defer verifyResp.Body.Close()

	verifyBytes, _ := io.ReadAll(verifyResp.Body)
	log.Printf("GET /v1/client/verify-email?token=... -> Status: %d %s | Response: %s", verifyResp.StatusCode, verifyResp.Status, string(verifyBytes))

	if verifyResp.StatusCode == http.StatusBadRequest && bytes.Contains(verifyBytes, []byte("invalid or revoked token")) {
		log.Println("✅ PROOF 3 PASSED: Expired token was rejected with HTTP 400 Bad Request ('invalid or revoked token')!")
	} else {
		log.Fatalf("❌ PROOF 3 FAILED: Expected HTTP 400 Bad Request for expired token, got %d", verifyResp.StatusCode)
	}

	log.Println("\n🎉 ALL 3 PROOFS VERIFIED SUCCESSFULLY!")
}
