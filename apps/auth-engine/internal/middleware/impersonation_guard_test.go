/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/impersonation_guard_test.go
 * Tier: Security Middleware Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware_test

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreventImpersonatedMutationsMiddleware(t *testing.T) {
	signingSecret := "test_encryption_key_32_bytes_12345"

	app := fiber.New()
	// nil blocklist: this case asserts the guard's method/path matrix, not JTI
	// revocation, and a nil *tokenblocklist.Blocklist is a documented no-op.
	app.Use(middleware.PreventImpersonatedMutations(signingSecret, nil))

	// These routes mirror the real registered API surface exactly. A test that
	// asserts against paths the router does not serve passes while the actual
	// route goes unguarded, so the method and path of each must match the
	// handler registration.
	app.Get("/v1/client/user/profile", func(c *fiber.Ctx) error {
		return c.SendString("profile data")
	})
	app.Post("/v1/client/user/password", func(c *fiber.Ctx) error {
		return c.SendString("password updated")
	})
	app.Post("/v1/client/auth/2fa/totp/disable", func(c *fiber.Ctx) error {
		return c.SendString("2fa disabled")
	})
	app.Delete("/v1/client/auth/2fa/webauthn/credentials/:id", func(c *fiber.Ctx) error {
		return c.SendString("credential deleted")
	})

	// Standard User Token (Not Impersonated)
	stdToken, err := jwtpkg.IssueAccessToken("usr_std123", "tnt_00000000000000000000000000000001", "test", "user@example.com", "User", "user", signingSecret, 15*time.Minute)
	require.NoError(t, err)

	// Impersonated Token (IsImpersonated: true)
	impToken, err := jwtpkg.IssueImpersonationToken("usr_std123", "tnt_00000000000000000000000000000001", "test", "user@example.com", "User", "user", "usr_admin99", 15*time.Minute, signingSecret)
	require.NoError(t, err)

	// 1. Standard Token: GET Profile -> 200 OK
	req1 := httptest.NewRequest("GET", "/v1/client/user/profile", nil)
	req1.Header.Set("Authorization", "Bearer "+stdToken)
	resp1, err := app.Test(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// 2. Standard Token: POST Password -> 200 OK (not impersonated, allowed)
	req2 := httptest.NewRequest("POST", "/v1/client/user/password", nil)
	req2.Header.Set("Authorization", "Bearer "+stdToken)
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// 3. Impersonated Token: GET Profile -> 200 OK (Read-only allowed)
	req3 := httptest.NewRequest("GET", "/v1/client/user/profile", nil)
	req3.Header.Set("Authorization", "Bearer "+impToken)
	resp3, err := app.Test(req3)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	// 4. Impersonated Token: POST Password -> 403 Forbidden (Blocked by guard)
	req4 := httptest.NewRequest("POST", "/v1/client/user/password", nil)
	req4.Header.Set("Authorization", "Bearer "+impToken)
	resp4, err := app.Test(req4)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp4.StatusCode)

	// 5. Impersonated token: POST /2fa/totp/disable -> 403. The route is matched
	// on its real path, so an impersonator cannot strip the victim's TOTP by
	// addressing a spelling the guard fails to recognise.
	req5 := httptest.NewRequest("POST", "/v1/client/auth/2fa/totp/disable", nil)
	req5.Header.Set("Authorization", "Bearer "+impToken)
	resp5, err := app.Test(req5)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp5.StatusCode)

	// 6. A route ending in a variable segment: DELETE webauthn credential -> 403.
	req6 := httptest.NewRequest("DELETE", "/v1/client/auth/2fa/webauthn/credentials/cred_abc123", nil)
	req6.Header.Set("Authorization", "Bearer "+impToken)
	resp6, err := app.Test(req6)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp6.StatusCode)

	// 7. An impersonated token delivered by COOKIE rather than header must be
	// blocked. Cookies are the default for browser sessions, so a guard reading
	// only the Authorization header would see nothing and wave the request
	// through while RequireClientAuth then admits it from the cookie.
	req7 := httptest.NewRequest("POST", "/v1/client/user/password", nil)
	req7.AddCookie(&http.Cookie{Name: "authn_access_token", Value: impToken})
	resp7, err := app.Test(req7)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp7.StatusCode)

	// 8. The other cookie name (access_token) is honored the same way.
	req8 := httptest.NewRequest("POST", "/v1/client/auth/2fa/totp/disable", nil)
	req8.AddCookie(&http.Cookie{Name: "access_token", Value: impToken})
	resp8, err := app.Test(req8)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp8.StatusCode)

	// 9. Non-destructive route under an impersonated cookie session stays 200 —
	// the guard blocks by route policy, not blanket-deny.
	req9 := httptest.NewRequest("GET", "/v1/client/user/profile", nil)
	req9.AddCookie(&http.Cookie{Name: "authn_access_token", Value: impToken})
	resp9, err := app.Test(req9)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp9.StatusCode)
}

// TestImpersonatedSignOutIsBlocked covers the sign-out routes.
//
// An impersonation token names the target user in `sub` and carries no session
// claim, so sign-out resolves the victim's user ID and nothing else. On
// /logout-all that is enough: it revokes every session the victim owns, on every
// device, signing them out of an account the impersonator is only visiting. That
// is a destructive mutation of the target's account, which is what this guard
// exists to refuse — an impersonator who wants to end their own support session
// uses /v1/client/auth/impersonate/exit, which is deliberately not on the list.
func TestImpersonatedSignOutIsBlocked(t *testing.T) {
	signingSecret := "test_encryption_key_32_bytes_12345"

	app := fiber.New()
	app.Use(middleware.PreventImpersonatedMutations(signingSecret, nil))
	app.Post("/v1/client/auth/logout", func(c *fiber.Ctx) error {
		return c.SendString("signed out")
	})
	app.Post("/v1/client/auth/logout-all", func(c *fiber.Ctx) error {
		return c.SendString("signed out everywhere")
	})
	app.Post("/v1/client/auth/impersonate/exit", func(c *fiber.Ctx) error {
		return c.SendString("impersonation ended")
	})

	stdToken, err := jwtpkg.IssueAccessToken("usr_std123", "tnt_00000000000000000000000000000001", "test", "user@example.com", "User", "user", signingSecret, 15*time.Minute)
	require.NoError(t, err)
	impToken, err := jwtpkg.IssueImpersonationToken("usr_std123", "tnt_00000000000000000000000000000001", "test", "user@example.com", "User", "usr_admin99", "usr_admin99", 15*time.Minute, signingSecret)
	require.NoError(t, err)

	for _, path := range []string{"/v1/client/auth/logout", "/v1/client/auth/logout-all"} {
		// The victim's own token signs out normally: the guard blocks by who is
		// asking, not by route.
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("Authorization", "Bearer "+stdToken)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "own token on %s", path)

		req = httptest.NewRequest("POST", path, nil)
		req.Header.Set("Authorization", "Bearer "+impToken)
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "impersonated token on %s", path)

		// Cookie delivery is the browser default, so it must be blocked too.
		req = httptest.NewRequest("POST", path, nil)
		req.AddCookie(&http.Cookie{Name: "authn_access_token", Value: impToken})
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "impersonated cookie on %s", path)
	}

	// Ending the impersonation itself stays reachable, otherwise blocking sign-out
	// would strand the impersonator in the session.
	req := httptest.NewRequest("POST", "/v1/client/auth/impersonate/exit", nil)
	req.Header.Set("Authorization", "Bearer "+impToken)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestImpersonationGuardLogsUnverifiableToken pins the observability of the
// fail-open path.
//
// The guard stops evaluating on both a missing and an unverifiable token. The
// unverifiable case is logged, because a guard that stops without saying so is
// indistinguishable from one that is working.
//
// The assertions are deliberately two-sided: the warning must appear, AND the
// token must not.
func TestImpersonationGuardLogsUnverifiableToken(t *testing.T) {
	signingSecret := "test_encryption_key_32_bytes_12345"

	app := fiber.New()
	app.Use(middleware.PreventImpersonatedMutations(signingSecret, nil))
	app.Post("/v1/client/user/password", func(c *fiber.Ctx) error {
		return c.SendString("password updated")
	})

	captureLogs := func(fn func()) string {
		var buf bytes.Buffer
		origOut, origFlags := log.Writer(), log.Flags()
		log.SetOutput(&buf)
		log.SetFlags(0)
		defer func() {
			log.SetOutput(origOut)
			log.SetFlags(origFlags)
		}()
		fn()
		return buf.String()
	}

	// A token signed with the WRONG secret: structurally a real JWT, so it gets
	// past ExtractAccessToken and fails at signature verification.
	foreignToken, err := jwtpkg.IssueAccessToken("usr_x", "tnt_00000000000000000000000000000001", "test", "x@example.com", "X", "user", "a_completely_different_signing_secret_1", 15*time.Minute)
	require.NoError(t, err)

	// 1. Unverifiable token -> request still proceeds (fail-open preserved) AND a
	//    warning is emitted naming the method and path.
	out := captureLogs(func() {
		req := httptest.NewRequest("POST", "/v1/client/user/password", nil)
		req.Header.Set("Authorization", "Bearer "+foreignToken)
		resp, err := app.Test(req)
		require.NoError(t, err)
		// An unverifiable token is not this guard's to reject: downstream auth is
		// what refuses it. The guard's obligation here is the warning.
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"the guard observes an unverifiable token; it must not fail closed on one")
	})

	assert.Contains(t, out, "impersonation guard skipped",
		"an unverifiable token must produce a warning, not silence")
	assert.Contains(t, out, "POST")
	assert.Contains(t, out, "/v1/client/user/password")
	assert.Contains(t, out, "reason=bad_signature",
		"the failure category should be recorded so a pattern is greppable")

	// 2. The log must never carry token material. Assert on the whole token and
	//    on each of its three segments individually — a partial leak (e.g. the
	//    payload segment surfacing through a wrapped json error) is still a leak.
	assert.NotContains(t, out, foreignToken, "the raw token must never be logged")
	for _, seg := range strings.Split(foreignToken, ".") {
		require.NotEmpty(t, seg)
		assert.NotContains(t, out, seg,
			"no JWT segment (header/payload/signature) may appear in the log")
	}
	// The subject and email live inside the payload; neither should surface.
	assert.NotContains(t, out, "usr_x")
	assert.NotContains(t, out, "x@example.com")

	// 3. A request with NO token stays silent — logging every anonymous hit to
	//    /v1/client (login, signup, reset) would bury the signal above in noise.
	out = captureLogs(func() {
		req := httptest.NewRequest("POST", "/v1/client/user/password", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
	assert.NotContains(t, out, "impersonation guard skipped",
		"the no-credential path is normal traffic and must not be logged")

	// 4. A structurally malformed token is categorized distinctly from a
	//    well-formed one with a bad signature.
	out = captureLogs(func() {
		req := httptest.NewRequest("POST", "/v1/client/user/password", nil)
		req.Header.Set("Authorization", "Bearer not-a-jwt-at-all")
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
	assert.Contains(t, out, "reason=malformed")
}
