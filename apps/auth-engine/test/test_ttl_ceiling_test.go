//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/test_ttl_ceiling_test.go
 * Tier: Integration Tests / Test-Environment Lifetime Ceilings
 *
 * Drives the ceilings through a real sign-in, because a lifetime is decided in
 * four places that have to agree — the signed token, the session row it refreshes
 * against, the cookie carrying the refresh token, and the expires_in a client
 * schedules its next refresh from. Any one of them resolving the lifetime on its
 * own would leave a credential outliving the record behind it, or a client
 * refreshing on a schedule the token does not keep.
 *
 * The ceilings this suite boots with are far shorter than the deployment defaults
 * the harness configures, so nothing here can pass on a clamp that never ran.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"testing"
	"time"

	entsession "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// The ceilings under test. Both are far below the harness's 15-minute access and
// 720-hour refresh defaults, so a lifetime matching either ceiling can only have
// come from the clamp.
const (
	ceilingAccessTokenTTL = 2 * time.Minute
	ceilingSessionTTL     = time.Hour
)

// ttlTolerance absorbs the wall-clock cost of the request being measured. The
// clamped and unclamped lifetimes differ by minutes and by weeks respectively, so
// it cannot mask a ceiling that failed to apply.
const ttlTolerance = 30 * time.Second

// loginReply is the subset of a sign-in response this suite reads.
type loginReply struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// sessionExpiry returns when the tenant's most recently opened test session
// expires, read outside the request path so it reports what was stored rather than
// what a response claimed.
func (e *testEnv) sessionExpiry(t *testing.T, sessionID string) time.Time {
	t.Helper()

	ctx := e.bypassContext()
	sess, err := e.client(ctx).Session.Query().
		Where(entsession.ID(sessionID)).
		Only(ctx)
	if err != nil {
		t.Fatalf("reading session %s: %v", sessionID, err)
	}
	return sess.ExpiresAt
}

// TestTestEnvironmentCeilingsBoundEverySignInArtifact is the ceiling's contract at
// the HTTP boundary: one sign-in with a test key, and every credential it produced
// expires inside the ceiling for its kind.
func TestTestEnvironmentCeilingsBoundEverySignInArtifact(t *testing.T) {
	env := newTestEnv(t, nil, nil, withTTLCeilings(ceilingAccessTokenTTL, ceilingSessionTTL))

	const address = "ttl_ceiling@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "TTL Ceiling"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	before := time.Now()
	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}

	var reply loginReply
	loginResp.json(t, &reply)
	if reply.AccessToken == "" {
		t.Fatalf("login returned no access token; body %s", loginResp.body)
	}

	claims, err := jwtpkg.VerifyAccessToken(reply.AccessToken, env.cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("verifying the access token: %v", err)
	}

	// The signed token. This is the artifact that matters most: it authenticates
	// requests on its own, with nothing to check it against until it expires.
	tokenLife := time.Unix(claims.Exp, 0).Sub(before)
	if tokenLife > ceilingAccessTokenTTL+ttlTolerance {
		t.Errorf("the access token lives %v, past the %v ceiling", tokenLife, ceilingAccessTokenTTL)
	}
	if tokenLife <= 0 {
		t.Errorf("the access token expires at %v, before the sign-in that issued it", time.Unix(claims.Exp, 0))
	}

	// The session row. This is what makes the refresh token work, so a row past the
	// ceiling keeps minting access tokens no matter how short each one is.
	if claims.SessionID == "" {
		t.Fatal("the access token carries no sid claim, so its session cannot be found")
	}
	sessionLife := env.sessionExpiry(t, claims.SessionID).Sub(before)
	if sessionLife > ceilingSessionTTL+ttlTolerance {
		t.Errorf("the session row lives %v, past the %v ceiling", sessionLife, ceilingSessionTTL)
	}

	// The refresh cookie, which must not outlive the row it refreshes against — a
	// browser holding a cookie for a deleted session refreshes into a 401 it cannot
	// distinguish from theft detection.
	cookie := loginResp.cookie(refreshCookieName)
	if cookie == nil {
		t.Fatalf("login set no %s cookie", refreshCookieName)
	}
	if cookie.Expires.IsZero() {
		t.Fatal("the refresh cookie carries no expiry, so it is a session cookie")
	}
	cookieLife := cookie.Expires.Sub(before)
	if cookieLife > ceilingSessionTTL+ttlTolerance {
		t.Errorf("the refresh cookie lives %v, past the %v session ceiling", cookieLife, ceilingSessionTTL)
	}
}

// TestTestEnvironmentCeilingsSurviveARefresh checks the rotated pair, not just the
// pair a sign-in produced. Refresh is the path a long-running harness spends its
// life on, so a clamp applied only at sign-in would let a session that started
// inside the ceiling walk past it one rotation at a time.
func TestTestEnvironmentCeilingsSurviveARefresh(t *testing.T) {
	env := newTestEnv(t, nil, nil, withTTLCeilings(ceilingAccessTokenTTL, ceilingSessionTTL))

	const address = "ttl_ceiling_refresh@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "TTL Ceiling Refresh"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}
	initial := loginResp.cookie(refreshCookieName)
	if initial == nil {
		t.Fatalf("login set no %s cookie", refreshCookieName)
	}

	before := time.Now()
	rotateResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(initial))
	if rotateResp.status != http.StatusOK {
		t.Fatalf("refresh: got status %d, want 200; body %s", rotateResp.status, rotateResp.body)
	}

	var rotated loginReply
	rotateResp.json(t, &rotated)
	if rotated.AccessToken == "" {
		t.Fatalf("refresh returned no access token; body %s", rotateResp.body)
	}

	claims, err := jwtpkg.VerifyAccessToken(rotated.AccessToken, env.cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("verifying the rotated access token: %v", err)
	}
	if life := time.Unix(claims.Exp, 0).Sub(before); life > ceilingAccessTokenTTL+ttlTolerance {
		t.Errorf("the rotated access token lives %v, past the %v ceiling", life, ceilingAccessTokenTTL)
	}

	if claims.SessionID != "" {
		if life := env.sessionExpiry(t, claims.SessionID).Sub(before); life > ceilingSessionTTL+ttlTolerance {
			t.Errorf("the rotated session row lives %v, past the %v ceiling", life, ceilingSessionTTL)
		}
	}

	if cookie := rotateResp.cookie(refreshCookieName); cookie != nil && !cookie.Expires.IsZero() {
		if life := cookie.Expires.Sub(before); life > ceilingSessionTTL+ttlTolerance {
			t.Errorf("the rotated refresh cookie lives %v, past the %v session ceiling", life, ceilingSessionTTL)
		}
	}

	if want := int(ceilingAccessTokenTTL.Seconds()); rotated.ExpiresIn != want {
		t.Errorf("refresh advertises expires_in=%d, want %d from the clamped lifetime", rotated.ExpiresIn, want)
	}
}

// TestUnboundedEngineLeavesTestLifetimesAlone is the control. Without ceilings the
// test environment gets the deployment defaults, so the assertions above are
// measuring the clamp rather than a lifetime the harness was always going to
// produce.
func TestUnboundedEngineLeavesTestLifetimesAlone(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "ttl_unbounded@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "TTL Unbounded"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	before := time.Now()
	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}

	var reply loginReply
	loginResp.json(t, &reply)
	claims, err := jwtpkg.VerifyAccessToken(reply.AccessToken, env.cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("verifying the access token: %v", err)
	}

	if life := time.Unix(claims.Exp, 0).Sub(before); life <= ceilingAccessTokenTTL {
		t.Errorf("with no ceiling the access token lives %v, which the clamped assertions could not tell from a clamp", life)
	}
	if claims.SessionID != "" {
		if life := env.sessionExpiry(t, claims.SessionID).Sub(before); life <= ceilingSessionTTL {
			t.Errorf("with no ceiling the session row lives %v, no longer than the ceiling it is the control for", life)
		}
	}

	// The advertised lifetime is read through a refresh, the only reply that carries
	// one. Unclamped it must report the deployment default, so the clamped suite's
	// 120 is the ceiling talking rather than whatever this endpoint always says.
	initial := loginResp.cookie(refreshCookieName)
	if initial == nil {
		t.Fatalf("login set no %s cookie", refreshCookieName)
	}
	rotateResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(initial))
	if rotateResp.status != http.StatusOK {
		t.Fatalf("refresh: got status %d, want 200; body %s", rotateResp.status, rotateResp.body)
	}

	var rotated loginReply
	rotateResp.json(t, &rotated)
	if want := int(env.cfg.AccessTokenTTL.Seconds()); rotated.ExpiresIn != want {
		t.Errorf("with no ceiling refresh advertises expires_in=%d, want the deployment default %d",
			rotated.ExpiresIn, want)
	}
}
