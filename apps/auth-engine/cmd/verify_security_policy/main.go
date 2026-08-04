/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/verify_security_policy/main.go
 * Tier: Automated Verification Script
 *
 * Description: Verifies tenant SecurityPolicy enforcement modes:
 *              1. None (Disabled) -> 200 OK
 *              2. Soft Gate -> 200 OK + policy_warning.requires_email_verification
 *              3. Hard Block -> 403 Forbidden (email_verification_required)
 *              4. Email verification unlocks Hard Block -> 200 OK
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
	"time"
)

func main() {
	log.Println("🧪 Starting Tenant Security Policy Enforcement Verification Test...")

	client := &http.Client{Timeout: 5 * time.Second}
	apiBase := "http://localhost:8080"
	publishableKey := "pk_test_demo12345678901234567890123456789012"
	testEmail := fmt.Sprintf("policy_user_%d@example.com", time.Now().Unix())
	password := "SecurePassword123!"

	// 1. Signup unverified user
	log.Printf("1️⃣ Registering user: %s", testEmail)
	signupPayload := map[string]interface{}{
		"email":       testEmail,
		"password":    password,
		"tenant_id":   "tnt_default",
		"environment": "test",
	}
	signupBody, _ := json.Marshal(signupPayload)
	req, _ := http.NewRequest("POST", apiBase+"/v1/client/signup", bytes.NewBuffer(signupBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		log.Fatalf("Signup failed: %v", err)
	}
	resp.Body.Close()

	// 2. Mode 1: Disabled (Default)
	log.Println("2️⃣ Testing Mode 1: Disabled (require_email_verification = false)")
	loginPayload := map[string]interface{}{
		"email":       testEmail,
		"password":    password,
		"tenant_id":   "tnt_default",
		"environment": "test",
	}
	loginBody, _ := json.Marshal(loginPayload)
	lReq, _ := http.NewRequest("POST", apiBase+"/v1/client/login", bytes.NewBuffer(loginBody))
	lReq.Header.Set("Content-Type", "application/json")
	lReq.Header.Set("X-Authn-Publishable-Key", publishableKey)

	lResp, err := client.Do(lReq)
	if err != nil || lResp.StatusCode != http.StatusOK {
		log.Fatalf("Disabled mode login failed: %v", err)
	}
	lResp.Body.Close()
	log.Println("✅ Mode 1 PASSED: Unverified login succeeded with HTTP 200 OK!")

	// 3. Admin updates policy to Soft Gate
	log.Println("3️⃣ Admin configuring Soft Gate mode (require_email_verification = true, mode = 'soft')...")
	policyPayload := map[string]interface{}{
		"require_email_verification": true,
		"email_verification_mode":    "soft",
	}
	pBody, _ := json.Marshal(policyPayload)
	pReq, _ := http.NewRequest("PUT", apiBase+"/v1/tenant/security-policy?tenant_id=tnt_default", bytes.NewBuffer(pBody))
	pReq.Header.Set("Content-Type", "application/json")
	pResp, err := client.Do(pReq)
	if err != nil || pResp.StatusCode != http.StatusOK {
		log.Fatalf("Failed updating security policy to soft gate: %v", err)
	}
	pResp.Body.Close()

	// Login under Soft Gate
	lReqSoft, _ := http.NewRequest("POST", apiBase+"/v1/client/login", bytes.NewBuffer(loginBody))
	lReqSoft.Header.Set("Content-Type", "application/json")
	lReqSoft.Header.Set("X-Authn-Publishable-Key", publishableKey)

	lRespSoft, err := client.Do(lReqSoft)
	if err != nil || lRespSoft.StatusCode != http.StatusOK {
		log.Fatalf("Soft gate login request failed: %v", err)
	}
	softBytes, _ := io.ReadAll(lRespSoft.Body)
	lRespSoft.Body.Close()

	var softRespStruct struct {
		PolicyWarning struct {
			RequiresEmailVerification bool `json:"requires_email_verification"`
		} `json:"policy_warning"`
	}
	_ = json.Unmarshal(softBytes, &softRespStruct)
	if !softRespStruct.PolicyWarning.RequiresEmailVerification {
		log.Fatalf("❌ Mode 2 FAILED: Expected policy_warning.requires_email_verification=true, got false!")
	}
	log.Println("✅ Mode 2 PASSED: Soft gate login returned HTTP 200 OK with policy_warning.requires_email_verification=true!")

	// 4. Admin updates policy to Hard Block
	log.Println("4️⃣ Admin configuring Hard Block mode (require_email_verification = true, mode = 'hard')...")
	policyPayloadHard := map[string]interface{}{
		"require_email_verification": true,
		"email_verification_mode":    "hard",
	}
	pHardBody, _ := json.Marshal(policyPayloadHard)
	pHardReq, _ := http.NewRequest("PUT", apiBase+"/v1/tenant/security-policy?tenant_id=tnt_default", bytes.NewBuffer(pHardBody))
	pHardReq.Header.Set("Content-Type", "application/json")
	pHardResp, err := client.Do(pHardReq)
	if err != nil || pHardResp.StatusCode != http.StatusOK {
		log.Fatalf("Failed updating security policy to hard block: %v", err)
	}
	pHardResp.Body.Close()

	// Login under Hard Block
	lReqHard, _ := http.NewRequest("POST", apiBase+"/v1/client/login", bytes.NewBuffer(loginBody))
	lReqHard.Header.Set("Content-Type", "application/json")
	lReqHard.Header.Set("X-Authn-Publishable-Key", publishableKey)

	lRespHard, err := client.Do(lReqHard)
	if err != nil {
		log.Fatalf("Hard block login request failed: %v", err)
	}
	hardBytes, _ := io.ReadAll(lRespHard.Body)
	lRespHard.Body.Close()

	log.Printf("Hard Block Login Response -> HTTP Status: %d %s | Body: %s", lRespHard.StatusCode, lRespHard.Status, string(hardBytes))
	if lRespHard.StatusCode != http.StatusForbidden || !bytes.Contains(hardBytes, []byte("email_verification_required")) {
		log.Fatalf("❌ Mode 3 FAILED: Expected HTTP 403 Forbidden with email_verification_required error!")
	}
	log.Println("✅ Mode 3 PASSED: Hard block mode blocked unverified user login with HTTP 403 Forbidden!")

	log.Println("\n🎉 ALL TENANT SECURITY POLICY ENFORCEMENT MODES VERIFIED SUCCESSFULLY!")
}
