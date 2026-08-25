//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/email_verification_test.go
 * Tier: Integration Tests / Email Verification & Tenant Policy
 *
 * Covers the email verification round trip and the tenant security policy that
 * decides what an unverified user may do:
 *
 *   disabled — verification is not required, login succeeds
 *   soft     — login succeeds but the reply carries a policy warning
 *   hard     — login is refused until the address is verified
 *
 * The policy modes are enforced in internal/auth/handler.go against the record
 * in internal/policy, neither of which has a unit test covering enforcement, so
 * these assertions are the only coverage of the gate.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

// signupReply is the subset of the signup response these tests assert on.
type signupReply struct {
	User struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"user"`
	PolicyWarning struct {
		RequiresEmailVerification bool `json:"requires_email_verification"`
	} `json:"policy_warning"`
}

// TestEmailVerificationRoundTrip walks the full verification flow: a new user
// starts unverified, the engine emails a link, following that link verifies the
// address, and a later login reports the account as verified.
//
// The verification token is read from the captured outbound email rather than
// from the database, so the assertion covers the link the user actually
// receives — a token that never reaches the message body would fail here.
func TestEmailVerificationRoundTrip(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "verify_roundtrip@example.com"
	const password = "SecurePass123!"

	signupResp := env.signUp(t, address, password, "Verification Tester")
	if signupResp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", signupResp.status, signupResp.body)
	}

	var created signupReply
	signupResp.json(t, &created)
	if created.User.EmailVerified {
		t.Fatal("a newly registered account reported email_verified=true before any link was followed")
	}

	token, ok := env.tokenFor(t, address)
	if !ok {
		t.Fatalf("no verification email carrying a token was sent to %s", address)
	}

	verifyResp := env.do(t, http.MethodGet,
		"/v1/client/auth/verify-email?token="+url.QueryEscape(token), nil)
	if verifyResp.status != http.StatusOK {
		t.Fatalf("verify-email: got status %d, want 200; body %s", verifyResp.status, verifyResp.body)
	}

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login after verification: got status %d, want 200; body %s",
			loginResp.status, loginResp.body)
	}

	var loggedIn signupReply
	loginResp.json(t, &loggedIn)
	if !loggedIn.User.EmailVerified {
		t.Error("account still reports email_verified=false after the verification link was followed")
	}
}

// TestEmailVerificationRejectsExpiredToken checks that a verification token
// past its expiry is refused. The token is planted directly with an expiry in
// the past, because waiting out the configured lifetime is not practical.
func TestEmailVerificationRejectsExpiredToken(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "expired_token_user@example.com"
	const rawToken = "expired_raw_token_1234567890abcdef1234567890abcdef"

	ctx := env.bypassContext()
	user, err := env.authRepo.CreateUser(ctx, "usr_expired_token", testTenant, testEnvironment,
		address, "unused_password_hash", "Expired Token User", "")
	if err != nil {
		t.Fatalf("creating the test user: %v", err)
	}

	digest := sha256.Sum256([]byte(rawToken))
	expiredAt := time.Now().Add(-time.Hour)
	if err := env.authRepo.SetUserEmailVerificationToken(ctx, user.ID, hex.EncodeToString(digest[:]), expiredAt); err != nil {
		t.Fatalf("planting an expired verification token: %v", err)
	}

	resp := env.do(t, http.MethodGet, "/v1/client/auth/verify-email?token="+url.QueryEscape(rawToken), nil)
	if resp.status != http.StatusBadRequest {
		t.Fatalf("expired verification token: got status %d, want 400; body %s", resp.status, resp.body)
	}
	if !strings.Contains(string(resp.body), "invalid or revoked token") {
		t.Errorf("expected the generic rejection message, got %s", resp.body)
	}
}

// TestEmailVerificationPolicyModes covers the three tenant policy settings that
// decide whether an unverified account may sign in.
//
// Each case gets its own engine so a policy change cannot leak into the next,
// and so the user it registers starts from a clean state.
func TestEmailVerificationPolicyModes(t *testing.T) {
	cases := []struct {
		name           string
		policy         policy.SecurityPolicy
		wantStatus     int
		wantWarning    bool
		wantBodySubstr string
	}{
		{
			name:        "disabled allows unverified login",
			policy:      policy.SecurityPolicy{RequireEmailVerification: false},
			wantStatus:  http.StatusOK,
			wantWarning: false,
		},
		{
			name: "soft allows login but flags the account",
			policy: policy.SecurityPolicy{
				RequireEmailVerification: true,
				EmailVerificationMode:    "soft",
			},
			wantStatus:  http.StatusOK,
			wantWarning: true,
		},
		{
			name: "hard refuses login until verified",
			policy: policy.SecurityPolicy{
				RequireEmailVerification: true,
				EmailVerificationMode:    "hard",
			},
			wantStatus:     http.StatusForbidden,
			wantBodySubstr: "email_verification_required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, nil, nil)

			if _, err := env.policyRepo.UpdateSecurityPolicy(env.bypassContext(), testTenant, "test", tc.policy); err != nil {
				t.Fatalf("applying the tenant security policy: %v", err)
			}

			const address = "policy_mode_user@example.com"
			const password = "SecurePassword123!"

			if resp := env.signUp(t, address, password, "Policy Mode User"); resp.status != http.StatusCreated {
				t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
			}

			loginResp := env.login(t, address, password)
			if loginResp.status != tc.wantStatus {
				t.Fatalf("login as an unverified user: got status %d, want %d; body %s",
					loginResp.status, tc.wantStatus, loginResp.body)
			}

			if tc.wantBodySubstr != "" && !strings.Contains(string(loginResp.body), tc.wantBodySubstr) {
				t.Errorf("expected the reply to name %q, got %s", tc.wantBodySubstr, loginResp.body)
			}

			if loginResp.status == http.StatusOK {
				var loggedIn signupReply
				loginResp.json(t, &loggedIn)
				if got := loggedIn.PolicyWarning.RequiresEmailVerification; got != tc.wantWarning {
					t.Errorf("policy_warning.requires_email_verification = %v, want %v; body %s",
						got, tc.wantWarning, loginResp.body)
				}
			}
		})
	}
}

// TestHardModeUnlocksAfterVerification checks the way out of a hard block: the
// same account that was refused signs in once its address is verified. Without
// this, a hard-mode tenant could lock every user out permanently and the
// refusal test alone would still pass.
func TestHardModeUnlocksAfterVerification(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	hardMode := policy.SecurityPolicy{
		RequireEmailVerification: true,
		EmailVerificationMode:    "hard",
	}
	if _, err := env.policyRepo.UpdateSecurityPolicy(env.bypassContext(), testTenant, "test", hardMode); err != nil {
		t.Fatalf("applying the hard-mode security policy: %v", err)
	}

	const address = "hard_mode_user@example.com"
	const password = "SuperSecret123!"

	signupResp := env.signUp(t, address, password, "Hard Mode User")
	if signupResp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", signupResp.status, signupResp.body)
	}

	var created signupReply
	signupResp.json(t, &created)
	if !created.PolicyWarning.RequiresEmailVerification {
		t.Errorf("signup under hard mode did not warn that verification is required; body %s", signupResp.body)
	}

	if resp := env.login(t, address, password); resp.status != http.StatusForbidden {
		t.Fatalf("login before verification: got status %d, want 403; body %s", resp.status, resp.body)
	}

	token, ok := env.tokenFor(t, address)
	if !ok {
		t.Fatalf("no verification email carrying a token was sent to %s", address)
	}
	if resp := env.do(t, http.MethodGet, "/v1/client/auth/verify-email?token="+url.QueryEscape(token), nil); resp.status != http.StatusOK {
		t.Fatalf("verify-email: got status %d, want 200; body %s", resp.status, resp.body)
	}

	if resp := env.login(t, address, password); resp.status != http.StatusOK {
		t.Fatalf("login after verification: got status %d, want 200; body %s", resp.status, resp.body)
	}
}
