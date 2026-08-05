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

	app.Get("/v1/client/user/profile", func(c *fiber.Ctx) error {
		return c.SendString("profile data")
	})
	app.Put("/v1/client/user/password", func(c *fiber.Ctx) error {
		return c.SendString("password updated")
	})
	app.Delete("/v1/client/2fa/totp", func(c *fiber.Ctx) error {
		return c.SendString("2fa disabled")
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

	// 2. Standard Token: PUT Password -> 200 OK
	req2 := httptest.NewRequest("PUT", "/v1/client/user/password", nil)
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

	// 4. Impersonated Token: PUT Password -> 403 Forbidden (Blocked by guard)
	req4 := httptest.NewRequest("PUT", "/v1/client/user/password", nil)
	req4.Header.Set("Authorization", "Bearer "+impToken)
	resp4, err := app.Test(req4)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp4.StatusCode)

	// 5. Impersonated Token: DELETE 2FA -> 403 Forbidden (Blocked by guard)
	req5 := httptest.NewRequest("DELETE", "/v1/client/2fa/totp", nil)
	req5.Header.Set("Authorization", "Bearer "+impToken)
	resp5, err := app.Test(req5)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp5.StatusCode)
}
