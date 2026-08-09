//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/refresh_token_test.go
 * Tier: Integration Tests / Refresh Token Rotation
 *
 * Covers the refresh-token lifecycle end to end through the OAuth token
 * endpoint: rotation on use, the grace window that keeps concurrent in-flight
 * requests alive, and the reuse detection that revokes a session family when a
 * superseded token comes back after the window has closed.
 *
 * internal/session carries the rotation logic and has no unit tests of its own,
 * so these are the only assertions covering that behaviour.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"testing"
	"time"
)

// refreshCookieName is the cookie the engine stores a browser session's refresh
// token in.
const refreshCookieName = "authn_refresh_token"

// refreshRequest is the OAuth token-endpoint body for a refresh exchange. The
// token itself travels in the cookie for browser clients and in this body for
// native ones.
type refreshRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// tokenResponse is the subset of the OAuth token reply these tests assert on.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TestRefreshTokenRotatesOnUse checks that exchanging a refresh token issues a
// new access token and replaces the refresh token, so a captured cookie is
// worthless once the legitimate client has refreshed.
func TestRefreshTokenRotatesOnUse(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "rotation_user@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "Rotation User"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}

	initial := loginResp.cookie(refreshCookieName)
	if initial == nil {
		t.Fatalf("login did not set the %s cookie; a browser client would have no session to refresh", refreshCookieName)
	}

	rotateResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(initial))
	if rotateResp.status != http.StatusOK {
		t.Fatalf("refresh: got status %d, want 200; body %s", rotateResp.status, rotateResp.body)
	}

	var rotated tokenResponse
	rotateResp.json(t, &rotated)
	if rotated.AccessToken == "" {
		t.Error("refresh returned no access token")
	}

	rotatedCookie := rotateResp.cookie(refreshCookieName)
	if rotatedCookie == nil {
		t.Fatalf("refresh did not set a replacement %s cookie", refreshCookieName)
	}
	if rotatedCookie.Value == initial.Value {
		t.Error("refresh token was not rotated: the reply carries the same token that was presented")
	}
}

// TestRefreshTokenGraceWindow covers both sides of the grace window. Inside it
// a superseded token still answers, so requests already in flight when a
// rotation lands are not all logged out. Outside it the same token is treated
// as theft: it is refused, and the successor token that replaced it is revoked
// too, because a token turning up after rotation means a copy exists.
func TestRefreshTokenGraceWindow(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "grace_user@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "Grace User"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}
	initial := loginResp.cookie(refreshCookieName)
	if initial == nil {
		t.Fatalf("login did not set the %s cookie", refreshCookieName)
	}

	rotateResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(initial))
	if rotateResp.status != http.StatusOK {
		t.Fatalf("first refresh: got status %d, want 200; body %s", rotateResp.status, rotateResp.body)
	}
	successor := rotateResp.cookie(refreshCookieName)
	if successor == nil {
		t.Fatalf("first refresh did not set a replacement %s cookie", refreshCookieName)
	}

	// Inside the window: the superseded token still works.
	insideResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(initial))
	if insideResp.status != http.StatusOK {
		t.Fatalf("reuse inside the grace window: got status %d, want 200; body %s",
			insideResp.status, insideResp.body)
	}

	// Let the window close. The margin absorbs scheduling jitter so the test
	// does not flake by racing the expiry it is trying to observe.
	time.Sleep(sessionGracePeriod + 500*time.Millisecond)

	outsideResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(initial))
	if outsideResp.status != http.StatusUnauthorized {
		t.Fatalf("reuse past the grace window: got status %d, want 401; body %s",
			outsideResp.status, outsideResp.body)
	}

	// Detecting reuse must also revoke the successor: if a superseded token is
	// circulating, the token that replaced it cannot be trusted either.
	successorResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(successor))
	if successorResp.status != http.StatusUnauthorized {
		t.Fatalf("successor token after reuse detection: got status %d, want 401; "+
			"the live session survived a detected theft; body %s",
			successorResp.status, successorResp.body)
	}
}

// TestRefreshTokenNativeClientPath checks the non-browser path, where the
// refresh token travels in the JSON body and comes back in the JSON reply
// rather than in a cookie.
func TestRefreshTokenNativeClientPath(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "native_user@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "Native User"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	loginResp := env.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
	if loginResp.status != http.StatusOK {
		t.Fatalf("native login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}

	var loggedIn tokenResponse
	loginResp.json(t, &loggedIn)
	if loggedIn.RefreshToken == "" {
		t.Fatalf("native login returned no refresh_token in the body; body %s", loginResp.body)
	}

	refreshResp := env.do(t, http.MethodPost, "/v1/oauth/token", refreshRequest{
		GrantType:    "refresh_token",
		RefreshToken: loggedIn.RefreshToken,
	})
	if refreshResp.status != http.StatusOK {
		t.Fatalf("native refresh: got status %d, want 200; body %s", refreshResp.status, refreshResp.body)
	}

	var refreshed tokenResponse
	refreshResp.json(t, &refreshed)
	if refreshed.AccessToken == "" {
		t.Error("native refresh returned no access token")
	}
	if refreshed.RefreshToken == "" {
		t.Error("native refresh returned no rotated refresh token in the body")
	}
	if refreshed.RefreshToken == loggedIn.RefreshToken {
		t.Error("native refresh did not rotate the refresh token")
	}
}

// TestRefreshTokenRejectsUnknownToken checks that a token the engine never
// issued is refused, rather than being treated as an unrecognised-but-harmless
// input.
func TestRefreshTokenRejectsUnknownToken(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	cases := []struct {
		name  string
		token string
	}{
		{name: "garbage", token: "garbage_invalid_token_123456789"},
		{name: "empty", token: ""},
		{name: "plausible shape", token: "rt_0000000000000000000000000000000000000000"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.do(t, http.MethodPost, "/v1/oauth/token", refreshRequest{
				GrantType:    "refresh_token",
				RefreshToken: tc.token,
			})
			if resp.status != http.StatusUnauthorized && resp.status != http.StatusBadRequest {
				t.Errorf("refresh with a %s token: got status %d, want 401 or 400; body %s",
					tc.name, resp.status, resp.body)
			}
		})
	}
}
