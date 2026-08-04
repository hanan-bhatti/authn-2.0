/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/verify_email/main.go
 * Tier: Automated Verification Script
 *
 * Description: End-to-end integration test verifying real email delivery over SMTP to
 *              Mailpit local catcher, token verification, and email_verified state updates.
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
	"net/url"
	"strings"
	"time"
)

type MailpitMessageSummary struct {
	ID      string   `json:"ID"`
	From    struct { Address string `json:"Address"` } `json:"From"`
	To      []struct{ Address string `json:"Address"` } `json:"To"`
	Subject string   `json:"Subject"`
}

type MailpitMessagesResponse struct {
	Messages []MailpitMessageSummary `json:"messages"`
}

type MailpitMessageDetail struct {
	ID   string `json:"ID"`
	HTML string `json:"HTML"`
	Text string `json:"Text"`
}

func main() {
	log.Println("🧪 Starting FR-3 Email Verification End-to-End Test...")

	client := &http.Client{Timeout: 10 * time.Second}
	apiBase := "http://localhost:8080"
	mailpitAPIBase := "http://localhost:8025/api/v1"
	publishableKey := "pk_test_demo12345678901234567890123456789012"

	testEmail := fmt.Sprintf("test_user_%d@example.com", time.Now().Unix())
	password := "SecurePass123!"
	name := "Mailpit Verification Tester"

	// 1. Signup Request
	log.Printf("1️⃣ Registering new user: %s", testEmail)
	signupPayload := map[string]interface{}{
		"email":       testEmail,
		"password":    password,
		"name":        name,
		"tenant_id":   "tnt_default",
		"environment": "test",
	}
	signupBody, _ := json.Marshal(signupPayload)
	req, err := http.NewRequest("POST", apiBase+"/v1/client/signup", bytes.NewBuffer(signupBody))
	if err != nil {
		log.Fatalf("Failed creating signup request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Signup HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Signup failed with status %d: %s", resp.StatusCode, string(respBytes))
	}

	var signupResp struct {
		User struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"user"`
	}
	if err := json.Unmarshal(respBytes, &signupResp); err != nil {
		log.Fatalf("Failed parsing signup response: %v", err)
	}

	log.Printf("✅ User created: ID=%s, EmailVerified=%v", signupResp.User.ID, signupResp.User.EmailVerified)
	if signupResp.User.EmailVerified {
		log.Fatalf("❌ Error: Expected email_verified=false on signup, got true!")
	}

	// 2. Poll Mailpit API for sent email
	log.Println("2️⃣ Polling Mailpit REST API for verification email...")
	time.Sleep(1 * time.Second) // allow SMTP async transmission

	mailpitReq, _ := http.NewRequest("GET", mailpitAPIBase+"/messages", nil)
	mailpitResp, err := client.Do(mailpitReq)
	if err != nil {
		log.Fatalf("Failed querying Mailpit messages API: %v", err)
	}
	defer mailpitResp.Body.Close()

	mailpitBytes, _ := io.ReadAll(mailpitResp.Body)
	var messagesList MailpitMessagesResponse
	if err := json.Unmarshal(mailpitBytes, &messagesList); err != nil {
		log.Fatalf("Failed parsing Mailpit messages JSON: %v", err)
	}

	var targetMsgID string
	for _, msg := range messagesList.Messages {
		for _, to := range msg.To {
			if to.Address == testEmail {
				targetMsgID = msg.ID
				break
			}
		}
	}

	if targetMsgID == "" {
		log.Fatalf("❌ Error: Verification email for %s was not found in Mailpit inbox!", testEmail)
	}
	log.Printf("📧 Email captured in Mailpit! Message ID: %s", targetMsgID)

	// 3. Inspect Mailpit email content & extract verification link
	detailReq, _ := http.NewRequest("GET", mailpitAPIBase+"/message/"+targetMsgID, nil)
	detailResp, err := client.Do(detailReq)
	if err != nil {
		log.Fatalf("Failed fetching Mailpit message detail: %v", err)
	}
	defer detailResp.Body.Close()

	detailBytes, _ := io.ReadAll(detailResp.Body)
	var msgDetail MailpitMessageDetail
	_ = json.Unmarshal(detailBytes, &msgDetail)

	log.Println("3️⃣ Extracting verification token link from email body...")
	contentToSearch := msgDetail.HTML
	if contentToSearch == "" {
		contentToSearch = msgDetail.Text
	}

	idx := strings.Index(contentToSearch, "/v1/client/verify-email?token=")
	if idx == -1 {
		log.Fatalf("❌ Error: Verification token URL missing in email body content!")
	}

	sub := contentToSearch[idx:]
	endIdx := strings.IndexAny(sub, "\"'\r\n\t <")
	if endIdx != -1 {
		sub = sub[:endIdx]
	}

	fullVerifyURL := apiBase + sub
	log.Printf("🔗 Found verification URL: %s", fullVerifyURL)

	parsedURL, err := url.Parse(fullVerifyURL)
	if err != nil {
		log.Fatalf("Failed parsing URL: %v", err)
	}
	tokenParam := parsedURL.Query().Get("token")
	if tokenParam == "" {
		log.Fatalf("❌ Error: Extracted URL has empty token parameter!")
	}

	// 4. Execute Verification Request
	log.Printf("4️⃣ Sending GET %s", fullVerifyURL)
	verifyReq, _ := http.NewRequest("GET", fullVerifyURL, nil)
	verifyReq.Header.Set("X-Authn-Publishable-Key", publishableKey)

	verifyResp, err := client.Do(verifyReq)
	if err != nil {
		log.Fatalf("Verification request failed: %v", err)
	}
	defer verifyResp.Body.Close()

	verifyBytes, _ := io.ReadAll(verifyResp.Body)
	if verifyResp.StatusCode != http.StatusOK {
		log.Fatalf("Verification endpoint returned status %d: %s", verifyResp.StatusCode, string(verifyBytes))
	}
	log.Printf("✅ Verification endpoint response: %s", string(verifyBytes))

	// 5. Verify User Profile / Login status updated to email_verified = true
	log.Println("5️⃣ Performing Login to confirm user.email_verified == true...")
	loginPayload := map[string]interface{}{
		"email":       testEmail,
		"password":    password,
		"tenant_id":   "tnt_default",
		"environment": "test",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginReq, _ := http.NewRequest("POST", apiBase+"/v1/client/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("X-Authn-Publishable-Key", publishableKey)

	loginResp, err := client.Do(loginReq)
	if err != nil {
		log.Fatalf("Login HTTP request failed: %v", err)
	}
	defer loginResp.Body.Close()

	loginBytes, _ := io.ReadAll(loginResp.Body)
	var loginResStruct struct {
		User struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		} `json:"user"`
	}
	if err := json.Unmarshal(loginBytes, &loginResStruct); err != nil {
		log.Fatalf("Failed parsing login response: %v", err)
	}

	if !loginResStruct.User.EmailVerified {
		log.Fatalf("❌ Error: Expected email_verified=true after verification, but got false!")
	}

	log.Println("🎉 SUCCESS! FR-3 Email Verification flow verified end-to-end with real SMTP delivery to Mailpit!")
}
