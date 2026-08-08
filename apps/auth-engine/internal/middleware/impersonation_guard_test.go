/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/impersonation_guard_test.go
 * Tier: Security Middleware Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware_test

import (
	"net/http"
	"net/http/httptest"
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
	app.Use(middleware.PreventImpersonatedMutations(signingSecret))

	// Routes below mirror the REAL registered API surface. The previous version
	// of this test used PUT /user/password and DELETE /2fa/totp — paths that do
	// not exist in the router — which is why it passed while the real
	// POST /2fa/totp/disable route went unguarded (audit H7).
	app.Get("/v1/client/user/profile", func(c *fiber.Ctx) error {
		return c.SendString("profile data")
	})
	app.Post("/v1/client/user/password", func(c *fiber.Ctx) error {
		return c.SendString("password updated")
	})
	app.Post("/v1/client/2fa/totp/disable", func(c *fiber.Ctx) error {
		return c.SendString("2fa disabled")
	})
	app.Delete("/v1/client/2fa/webauthn/credentials/:id", func(c *fiber.Ctx) error {
		return c.SendString("credential deleted")
	})

	// Standard User Token (Not Impersonated)
	stdToken, err := jwtpkg.IssueAccessToken("usr_std123", "tnt_default", "test", "user@example.com", "User", "user", signingSecret)
	require.NoError(t, err)

	// Impersonated Token (IsImpersonated: true)
	impToken, err := jwtpkg.IssueImpersonationToken("usr_std123", "tnt_default", "test", "user@example.com", "User", "user", "usr_admin99", 15*time.Minute, signingSecret)
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

	// 5. H7 regression — Impersonated Token: POST /2fa/totp/disable -> 403.
	// The old substring matcher looked for "/2fa/disable" and missed this real
	// route, letting an impersonator strip the victim's TOTP.
	req5 := httptest.NewRequest("POST", "/v1/client/2fa/totp/disable", nil)
	req5.Header.Set("Authorization", "Bearer "+impToken)
	resp5, err := app.Test(req5)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp5.StatusCode)

	// 6. H7 regression — param-tail route: DELETE webauthn credential -> 403.
	req6 := httptest.NewRequest("DELETE", "/v1/client/2fa/webauthn/credentials/cred_abc123", nil)
	req6.Header.Set("Authorization", "Bearer "+impToken)
	resp6, err := app.Test(req6)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp6.StatusCode)

	// 7. H6 regression — impersonated token delivered via COOKIE (not header)
	// must be blocked. Previously the guard read only the Authorization header,
	// so a cookie-authed impersonation session bypassed it entirely.
	req7 := httptest.NewRequest("POST", "/v1/client/user/password", nil)
	req7.AddCookie(&http.Cookie{Name: "authn_access_token", Value: impToken})
	resp7, err := app.Test(req7)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp7.StatusCode)

	// 8. H6 regression — same cookie name variant (access_token) is also honored.
	req8 := httptest.NewRequest("POST", "/v1/client/2fa/totp/disable", nil)
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
