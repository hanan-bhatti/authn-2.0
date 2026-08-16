//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/logout_test.go
 * Tier: Integration Test
 *
 * Covers POST /v1/client/auth/logout and /v1/client/auth/logout-all.
 *
 * The assertions read the session rows rather than replaying the refresh token,
 * because a refresh call rotates the session it succeeds against: probing with one
 * would change the state the next assertion is about. Reading the rows also states
 * the guarantee directly — sign-out has to end the server-side session, not merely
 * ask the browser to forget its cookie.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	entsession "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	entuser "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

// liveSessionCount returns how many of the user's sessions can still mint tokens.
//
// Revocation flips a status column rather than deleting the row, so counting rows
// would report a revoked session as live. Grace-window rows count as live too:
// their refresh token still answers with an access token until the window closes.
func (e *testEnv) liveSessionCount(t *testing.T, emailAddr string) int {
	t.Helper()

	ctx := e.bypassContext()
	client := e.factory.GetClient(ctx, testTenant, testEnvironment)

	u, err := client.User.Query().
		Where(entuser.EmailEQ(strings.ToLower(emailAddr))).
		Only(ctx)
	if err != nil {
		t.Fatalf("loading user %s: %v", emailAddr, err)
	}

	count, err := client.Session.Query().
		Where(
			entsession.UserID(u.ID),
			entsession.StatusNEQ(entsession.StatusRevoked),
		).
		Count(ctx)
	if err != nil {
		t.Fatalf("counting sessions for %s: %v", emailAddr, err)
	}
	return count
}

// TestLogoutRevokesSessionFromAccessToken signs out a caller presenting a valid
// access token and confirms the session behind it is gone.
//
// The final refresh attempt is the user-visible half of the guarantee: the token
// the client still holds has to stop being exchangeable.
func TestLogoutRevokesSessionFromAccessToken(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "logout_bearer@example.com"
	const password = "SuperSecret123!"
	if resp := env.signUp(t, address, password, "Logout Bearer"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}

	// Signup signs the user in, so the account already owns a session before it
	// ever logs in. Baselining against that is what lets the assertion below say
	// "this one session ended" rather than "some number of sessions ended".
	baseline := env.liveSessionCount(t, address)

	// The native client type returns the refresh token in the body, which is what
	// lets this test hold the raw token and replay it after signing out.
	loginResp := env.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: status %d body %s", loginResp.status, loginResp.body)
	}
	var tokens tokenResponse
	loginResp.json(t, &tokens)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("login returned no token pair: %s", loginResp.body)
	}

	if live := env.liveSessionCount(t, address); live != baseline+1 {
		t.Fatalf("login added %d live sessions, want 1", live-baseline)
	}

	resp := env.do(t, http.MethodPost, "/v1/client/auth/logout", map[string]any{},
		withHeader("Authorization", "Bearer "+tokens.AccessToken))
	if resp.status != http.StatusOK {
		t.Fatalf("logout: status %d body %s", resp.status, resp.body)
	}

	var out struct {
		SessionRevoked bool `json:"session_revoked"`
	}
	resp.json(t, &out)
	if !out.SessionRevoked {
		t.Fatalf("logout reported no session revoked: %s", resp.body)
	}

	// Back to the baseline and no lower: this route ends the caller's own session,
	// so the account's other sessions have to survive it.
	if live := env.liveSessionCount(t, address); live != baseline {
		t.Fatalf("after signing out one session, %d live sessions remain, want %d", live, baseline)
	}

	replay := env.do(t, http.MethodPost, "/v1/client/auth/refresh",
		map[string]string{"refresh_token": tokens.RefreshToken})
	if replay.status == http.StatusOK {
		t.Fatalf("refresh token still mints tokens after sign-out: %s", replay.body)
	}
}

// TestLogoutRevokesSessionFromCookieAlone signs out with only the refresh cookie
// and no access token.
//
// This is the case a real browser hits most: access tokens last minutes, so a tab
// left open past that lifetime has nothing but the cookie when the user clicks
// sign out. Resolving the session from the access token alone would clear the
// cookie and leave the session live for the rest of the refresh lifetime.
func TestLogoutRevokesSessionFromCookieAlone(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "logout_cookie@example.com"
	const password = "SuperSecret123!"
	if resp := env.signUp(t, address, password, "Logout Cookie"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}

	baseline := env.liveSessionCount(t, address)

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: status %d body %s", loginResp.status, loginResp.body)
	}
	cookie := loginResp.cookie(refreshCookieName)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("login set no refresh cookie")
	}
	if live := env.liveSessionCount(t, address); live != baseline+1 {
		t.Fatalf("login added %d live sessions, want 1", live-baseline)
	}

	// No Authorization header: the cookie is the only credential presented.
	resp := env.do(t, http.MethodPost, "/v1/client/auth/logout", map[string]any{},
		withCookie(cookie))
	if resp.status != http.StatusOK {
		t.Fatalf("logout: status %d body %s", resp.status, resp.body)
	}

	var out struct {
		SessionRevoked bool `json:"session_revoked"`
	}
	resp.json(t, &out)
	if !out.SessionRevoked {
		t.Fatalf("logout with only a cookie revoked nothing: %s", resp.body)
	}

	if live := env.liveSessionCount(t, address); live != baseline {
		t.Fatalf("after signing out with the cookie, %d live sessions remain, want %d", live, baseline)
	}
}

// TestLogoutClearsRefreshCookie confirms the reply instructs the browser to drop
// the cookie, which is what stops it being replayed at all.
func TestLogoutClearsRefreshCookie(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "logout_clears@example.com"
	const password = "SuperSecret123!"
	if resp := env.signUp(t, address, password, "Logout Clears"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}
	loginResp := env.login(t, address, password)
	issued := loginResp.cookie(refreshCookieName)
	if issued == nil {
		t.Fatal("login set no refresh cookie")
	}

	resp := env.do(t, http.MethodPost, "/v1/client/auth/logout", map[string]any{},
		withCookie(issued))

	cleared := resp.cookie(refreshCookieName)
	if cleared == nil {
		t.Fatal("logout sent no refresh cookie instruction")
	}
	if cleared.Value != "" {
		t.Fatal("logout returned a refresh cookie still carrying a value")
	}
	// An expiry in the past is how a cookie is removed rather than replaced, so it
	// must not still be sitting at the lifetime login handed out.
	if cleared.Expires.After(issued.Expires) {
		t.Fatalf("cleared cookie expires at %v, later than the issued %v, so it is not removed",
			cleared.Expires, issued.Expires)
	}
}

// TestLogoutWithoutCredentialsSucceeds drives sign-out with nothing to revoke.
//
// The endpoint is deliberately idempotent: a browser holding a token the server
// has already forgotten still needs the cookie removed, and refusing would leave
// it holding a credential it can neither use nor clear.
func TestLogoutWithoutCredentialsSucceeds(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.do(t, http.MethodPost, "/v1/client/auth/logout", map[string]any{})
	if resp.status != http.StatusOK {
		t.Fatalf("logout with no credential: status %d body %s", resp.status, resp.body)
	}

	var out struct {
		SessionRevoked bool `json:"session_revoked"`
	}
	resp.json(t, &out)
	if out.SessionRevoked {
		t.Fatalf("logout claimed to revoke a session it never had: %s", resp.body)
	}
}

// TestLogoutAllRevokesEverySession signs in twice, signs out of everything from
// one of those sessions, and confirms both are gone.
func TestLogoutAllRevokesEverySession(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "logout_all@example.com"
	const password = "SuperSecret123!"
	if resp := env.signUp(t, address, password, "Logout All"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}

	first := env.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
	second := env.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
	var firstTokens, secondTokens tokenResponse
	first.json(t, &firstTokens)
	second.json(t, &secondTokens)
	if firstTokens.RefreshToken == "" || secondTokens.RefreshToken == "" {
		t.Fatalf("expected two token pairs: %s / %s", first.body, second.body)
	}
	if firstTokens.RefreshToken == secondTokens.RefreshToken {
		t.Fatal("both logins returned the same refresh token, so there is only one session to revoke")
	}
	// Three sessions exist by this point: the one signup created and one per login.
	// logout-all has to take every one of them, the signup session included.
	const expectedSessions = 3
	if live := env.liveSessionCount(t, address); live != expectedSessions {
		t.Fatalf("expected %d live sessions before logout-all, found %d", expectedSessions, live)
	}

	resp := env.do(t, http.MethodPost, "/v1/client/auth/logout-all", map[string]any{},
		withHeader("Authorization", "Bearer "+secondTokens.AccessToken))
	if resp.status != http.StatusOK {
		t.Fatalf("logout-all: status %d body %s", resp.status, resp.body)
	}

	var out struct {
		Count int `json:"count"`
	}
	resp.json(t, &out)
	if out.Count != expectedSessions {
		t.Fatalf("logout-all reported %d sessions revoked, want %d", out.Count, expectedSessions)
	}

	if live := env.liveSessionCount(t, address); live != 0 {
		t.Fatalf("%d live sessions remain after logout-all", live)
	}

	// The other device's token is the one a caller would expect to survive a
	// per-session sign-out; on this route it must not.
	replay := env.do(t, http.MethodPost, "/v1/client/auth/refresh",
		map[string]string{"refresh_token": firstTokens.RefreshToken})
	if replay.status == http.StatusOK {
		t.Fatalf("the other device's refresh token still works after logout-all: %s", replay.body)
	}
}

// TestLogoutAllRequiresIdentifiedCaller confirms the all-devices variant refuses
// an anonymous request rather than reporting a successful no-op.
func TestLogoutAllRequiresIdentifiedCaller(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.do(t, http.MethodPost, "/v1/client/auth/logout-all", map[string]any{})
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("logout-all with no credential: status %d, want 401; body %s", resp.status, resp.body)
	}
}

// TestAdminSessionRoutesUnmountedWithoutGuard drives the admin session tier in a
// harness that supplied no admin middleware.
//
// Fiber accepts a nil handler at registration and dereferences it on the first
// request, so a handler that passed the nil straight to app.Group would answer
// this request with a panic inside the router rather than a status code. The
// route being absent is the intended outcome: an admin route that acts on a user
// ID from the path must not be reachable without the guard that authorises it.
func TestAdminSessionRoutesUnmountedWithoutGuard(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	for _, path := range []string{
		"/v1/admin/users/usr_someone/sessions",
		"/v1/admin/users/usr_someone/sessions/revoke-all",
	} {
		resp := env.do(t, http.MethodPost, path, map[string]any{})
		if resp.status != http.StatusNotFound {
			t.Fatalf("POST %s: status %d, want 404; body %s", path, resp.status, resp.body)
		}
	}
}

// TestLogoutAllFromCookieAlone signs out every device with only the refresh
// cookie, the state a browser is in once its access token has expired.
func TestLogoutAllFromCookieAlone(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "logout_all_cookie@example.com"
	const password = "SuperSecret123!"
	if resp := env.signUp(t, address, password, "Logout All Cookie"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}

	env.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
	browser := env.login(t, address, password)
	cookie := browser.cookie(refreshCookieName)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("browser login set no refresh cookie")
	}
	// One session from signup plus one per login.
	if live := env.liveSessionCount(t, address); live != 3 {
		t.Fatalf("expected 3 live sessions, found %d", live)
	}

	resp := env.do(t, http.MethodPost, "/v1/client/auth/logout-all", map[string]any{},
		withCookie(cookie))
	if resp.status != http.StatusOK {
		t.Fatalf("logout-all from cookie: status %d body %s", resp.status, resp.body)
	}

	if live := env.liveSessionCount(t, address); live != 0 {
		t.Fatalf("%d live sessions remain after logout-all from the cookie alone", live)
	}
}
