/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/verify_magic_link/main.go
 * Tier: Automated Verification Script
 *
 * Description: Tests Passwordless Magic Link flow end-to-end:
 *              1. Auto-provisions new user on magic link request (Option A)
 *              2. Captures real SMTP email via Mailpit REST API
 *              3. Verifies token, sets email_verified = true, issues access & refresh tokens
 *              4. Verifies single-use replay protection (second attempt fails with 400)
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type MailpitMessage struct {
	ID      string `json:"ID"`
	Subject string `json:"Subject"`
	Snippet string `json:"Snippet"`
}

type MailpitListResponse struct {
	Messages []MailpitMessage `json:"messages"`
}

type MailpitDetailResponse struct {
	Text string `json:"Text"`
	HTML string `json:"HTML"`
}

func main() {
	log.Println("🧪 Starting Passwordless Magic Link End-to-End Verification Test...")

	client := &http.Client{Timeout: 5 * time.Second}
	apiBase := "http://localhost:8080"
	mailpitBase := "http://localhost:8025"
	publishableKey := "pk_test_demo12345678901234567890123456789012"
	testEmail := fmt.Sprintf("magic_user_%d@example.com", time.Now().Unix())

	// 1. Request Magic Link for new user (Auto-signup test)
	log.Printf("1️⃣ Requesting Magic Link for new user (auto-provision test): %s", testEmail)
	reqPayload := map[string]interface{}{
		"email":       testEmail,
		"name":        "Magic Link Tester",
		"tenant_id":   "tnt_default",
		"environment": "test",
	}
	pBody, _ := json.Marshal(reqPayload)
	req, _ := http.NewRequest("POST", apiBase+"/v1/client/auth/magic-link", bytes.NewBuffer(pBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Fatalf("❌ Requesting magic link failed: status %d, err: %v", resp.StatusCode, err)
	}
	resp.Body.Close()
	log.Println("✅ Magic link request succeeded with HTTP 200 OK!")

	// 2. Poll Mailpit to fetch magic link token
	log.Println("2️⃣ Polling Mailpit REST API to capture delivered email...")
	time.Sleep(1 * time.Second)

	listResp, err := client.Get(mailpitBase + "/api/v1/messages")
	if err != nil || listResp.StatusCode != http.StatusOK {
		log.Fatalf("❌ Failed querying Mailpit REST API: %v", err)
	}
	listBytes, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()

	var mailList MailpitListResponse
	if err := json.Unmarshal(listBytes, &mailList); err != nil || len(mailList.Messages) == 0 {
		log.Fatalf("❌ No emails found in Mailpit inbox!")
	}

	latestID := mailList.Messages[0].ID
	detailResp, err := client.Get(fmt.Sprintf("%s/api/v1/message/%s", mailpitBase, latestID))
	if err != nil || detailResp.StatusCode != http.StatusOK {
		log.Fatalf("❌ Failed fetching email details from Mailpit: %v", err)
	}
	detailBytes, _ := io.ReadAll(detailResp.Body)
	detailResp.Body.Close()

	var detail MailpitDetailResponse
	_ = json.Unmarshal(detailBytes, &detail)

	fullContent := detail.Text + " " + detail.HTML
	tokenIdx := strings.Index(fullContent, "token=")
	if tokenIdx == -1 {
		log.Fatalf("❌ Could not find 'token=' in magic link email body: %s", fullContent)
	}

	rawTokenStr := fullContent[tokenIdx+6:]
	if endIdx := strings.IndexAny(rawTokenStr, " \t\r\n\"'<>&"); endIdx != -1 {
		rawTokenStr = rawTokenStr[:endIdx]
	}
	log.Printf("🔑 Extracted Raw Magic Link Token from Mailpit: %s", rawTokenStr)

	// 3. Verify Magic Link Token
	log.Println("3️⃣ Verifying Magic Link Token (POST /v1/client/auth/magic-link/verify)...")
	verifyPayload := map[string]interface{}{
		"token": rawTokenStr,
	}
	vBody, _ := json.Marshal(verifyPayload)
	vReq, _ := http.NewRequest("POST", apiBase+"/v1/client/auth/magic-link/verify", bytes.NewBuffer(vBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.Header.Set("X-Authn-Publishable-Key", publishableKey)

	vResp, err := client.Do(vReq)
	if err != nil {
		log.Fatalf("❌ Magic link verification request failed: %v", err)
	}
	vBytes, _ := io.ReadAll(vResp.Body)
	vResp.Body.Close()

	log.Printf("Verification Response -> Status: %d | Body: %s", vResp.StatusCode, string(vBytes))
	if vResp.StatusCode != http.StatusOK {
		log.Fatalf("❌ Verification failed with status %d", vResp.StatusCode)
	}

	var authResp struct {
		User struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"user"`
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(vBytes, &authResp)

	if authResp.User.Email != testEmail || !authResp.User.EmailVerified || authResp.AccessToken == "" {
		log.Fatalf("❌ Verification payload incomplete: user email_verified must be true and access_token non-empty!")
	}
	log.Println("✅ Magic link verification PASSED: User auto-provisioned, email_verified=true, Access Token issued!")

	// 4. Test Single-Use Replay Protection
	log.Println("4️⃣ Testing Single-Use Replay Protection (Reusing token)...")
	vReq2, _ := http.NewRequest("POST", apiBase+"/v1/client/auth/magic-link/verify", bytes.NewBuffer(vBody))
	vReq2.Header.Set("Content-Type", "application/json")
	vReq2.Header.Set("X-Authn-Publishable-Key", publishableKey)

	vResp2, err := client.Do(vReq2)
	if err != nil {
		log.Fatalf("❌ Replay test request failed: %v", err)
	}
	vBytes2, _ := io.ReadAll(vResp2.Body)
	vResp2.Body.Close()

	if vResp2.StatusCode != http.StatusBadRequest {
		log.Fatalf("❌ Replay protection FAILED: Expected HTTP 400 Bad Request, got %d: %s", vResp2.StatusCode, string(vBytes2))
	}
	log.Println("✅ Single-Use Replay Protection PASSED: Second attempt rejected with HTTP 400 Bad Request!")

	log.Println("\n🎉 PASSWORDLESS MAGIC LINK END-TO-END FLOW VERIFIED SUCCESSFULLY!")
}
