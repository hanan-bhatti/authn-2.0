//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/magic_link_test.go
 * Tier: Integration Tests / Passwordless Magic Link
 *
 * Covers the passwordless sign-in flow: requesting a link provisions an account
 * for an address the engine has not seen before, following the link verifies
 * the address and issues a session, and the link cannot be followed twice.
 *
 * internal/email has a unit test for the message template. Nothing covers the
 * token round trip, so these assertions are the only ones that would catch a
 * link that is rendered correctly but does not authenticate anyone.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"testing"
)

// magicLinkReply is the subset of the verification response asserted on here.
type magicLinkReply struct {
	User struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	} `json:"user"`
	AccessToken string `json:"access_token"`
}

// requestMagicLink asks the engine to email a sign-in link and fails the test
// if the request is not accepted.
func requestMagicLink(t *testing.T, env *testEnv, address string) {
	t.Helper()

	resp := env.do(t, http.MethodPost, "/v1/client/auth/magic-link", map[string]string{
		"email":       address,
		"name":        "Magic Link Tester",
		"tenant_id":   testTenant,
		"environment": testEnvironment,
	})
	if resp.status != http.StatusOK {
		t.Fatalf("magic-link request: got status %d, want 200; body %s", resp.status, resp.body)
	}
}

// TestMagicLinkProvisionsAndAuthenticates checks that a magic link sent to an
// unknown address creates the account, and that following the link both marks
// the address verified and issues a session.
//
// Arriving by magic link is itself proof the user controls the mailbox, which
// is why the account comes out verified without a separate confirmation step.
func TestMagicLinkProvisionsAndAuthenticates(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "magic_new_user@example.com"

	requestMagicLink(t, env, address)

	token, ok := env.tokenFor(t, address)
	if !ok {
		t.Fatalf("no magic-link email carrying a token was sent to %s", address)
	}

	resp := env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify",
		map[string]string{"token": token})
	if resp.status != http.StatusOK {
		t.Fatalf("magic-link verify: got status %d, want 200; body %s", resp.status, resp.body)
	}

	var verified magicLinkReply
	resp.json(t, &verified)

	if verified.User.Email != address {
		t.Errorf("session belongs to %q, want %q", verified.User.Email, address)
	}
	if !verified.User.EmailVerified {
		t.Error("following a magic link left the address unverified, though receiving it proves mailbox control")
	}
	if verified.AccessToken == "" {
		t.Error("magic-link verification issued no access token, so the user is not actually signed in")
	}
}

// TestMagicLinkIsSingleUse checks that a link stops working once redeemed. A
// magic link grants a session on its own, and copies survive in mailboxes,
// forwarded threads and mail-server logs long after use.
func TestMagicLinkIsSingleUse(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "magic_replay_user@example.com"

	requestMagicLink(t, env, address)

	token, ok := env.tokenFor(t, address)
	if !ok {
		t.Fatalf("no magic-link email carrying a token was sent to %s", address)
	}

	payload := map[string]string{"token": token}

	if resp := env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify", payload); resp.status != http.StatusOK {
		t.Fatalf("first redemption: got status %d, want 200; body %s", resp.status, resp.body)
	}

	replay := env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify", payload)
	if replay.status != http.StatusBadRequest {
		t.Fatalf("replayed magic link: got status %d, want 400; a redeemed link still grants a session; body %s",
			replay.status, replay.body)
	}
}

// TestMagicLinkRejectsUnknownToken checks that a token the engine never issued
// is refused rather than provisioning an account for whatever it decodes to.
func TestMagicLinkRejectsUnknownToken(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	cases := []struct {
		name  string
		token string
	}{
		{name: "garbage", token: "not_a_real_magic_link_token_000000"},
		{name: "empty", token: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify",
				map[string]string{"token": tc.token})
			if resp.status != http.StatusBadRequest {
				t.Errorf("verify with a %s token: got status %d, want 400; body %s",
					tc.name, resp.status, resp.body)
			}
		})
	}
}
