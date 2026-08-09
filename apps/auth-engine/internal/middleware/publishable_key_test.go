/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/publishable_key_test.go
 * Tier: Internal Feature Package / Middleware Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirePublishableKeyMiddleware(t *testing.T) {
	pepper := "test_pepper_key_32_bytes_long_12345"
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:pk_middleware_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeySvc := apikey.NewService(apiKeyRepo, pepper)

	// Seed Tenant A and Application A with Key A
	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tntA, err := client.Tenant.Create().SetID("tnt_A").SetName("Tenant A").SetSlug("tnt-a").Save(sysCtx)
	require.NoError(t, err)

	appA, err := client.Application.Create().SetID("app_A").SetTenantID(tntA.ID).SetName("App A").Save(sysCtx)
	require.NoError(t, err)

	rawKeyA := "pk_test_AAAA1234567890123456789012345678"
	err = apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_A", appA.ID, rawKeyA, pepper)
	require.NoError(t, err)

	// Seed Tenant B and Application B with Key B
	tntB, err := client.Tenant.Create().SetID("tnt_B").SetName("Tenant B").SetSlug("tnt-b").Save(sysCtx)
	require.NoError(t, err)

	appB, err := client.Application.Create().SetID("app_B").SetTenantID(tntB.ID).SetName("App B").Save(sysCtx)
	require.NoError(t, err)

	rawKeyB := "pk_test_BBBB1234567890123456789012345678"
	err = apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_B", appB.ID, rawKeyB, pepper)
	require.NoError(t, err)

	// Setup Fiber test App
	app := fiber.New()
	pkMw := middleware.RequirePublishableKey(apiKeySvc)

	app.Get("/v1/client/protected", pkMw, func(c *fiber.Ctx) error {
		p, ok := privacy.FromContext(c.UserContext())
		if !ok {
			return c.Status(fiber.StatusInternalServerError).SendString("no privacy context")
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"tenant_id":   p.TenantID,
			"environment": p.Environment,
		})
	})

	// 1. Request with NO publishable key header -> 401 Unauthorized
	req1 := httptest.NewRequest("GET", "/v1/client/protected", nil)
	resp1, err := app.Test(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp1.StatusCode)

	// 2. Request with invalid/garbage key -> 401 Unauthorized
	req2 := httptest.NewRequest("GET", "/v1/client/protected", nil)
	req2.Header.Set("X-Authn-Publishable-Key", "pk_test_invalid_garbage_key")
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// 3. Request with valid Key A -> 200 OK & scoped to Tenant A
	req3 := httptest.NewRequest("GET", "/v1/client/protected", nil)
	req3.Header.Set("X-Authn-Publishable-Key", rawKeyA)
	resp3, err := app.Test(req3)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	// 4. Request with valid Key B -> 200 OK & scoped to Tenant B
	req4 := httptest.NewRequest("GET", "/v1/client/protected", nil)
	req4.Header.Set("X-Authn-Publishable-Key", rawKeyB)
	resp4, err := app.Test(req4)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp4.StatusCode)
}

// TestPublishableKeyQueryFallbackScoping locks in audit finding M6: the
// publishable key used to be accepted from ?publishable_key= / ?pk= on EVERY
// route, which leaked it into access logs, browser history, and the Referer
// header of any outbound link on the landing page.
//
// The fallback is now restricted to the redirect-landing GET routes in
// pkQueryFallbackRoutes, which a browser reaches by 302 or by clicking an
// emailed link and therefore cannot attach a header to.
func TestPublishableKeyQueryFallbackScoping(t *testing.T) {
	pepper := "test_pepper_key_32_bytes_long_12345"
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:pk_query_scope_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeySvc := apikey.NewService(apiKeyRepo, pepper)

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tnt, err := client.Tenant.Create().SetID("tnt_Q").SetName("Tenant Q").SetSlug("tnt-q").Save(sysCtx)
	require.NoError(t, err)
	appQ, err := client.Application.Create().SetID("app_Q").SetTenantID(tnt.ID).SetName("App Q").Save(sysCtx)
	require.NoError(t, err)

	rawKey := "pk_test_QQQQ1234567890123456789012345678"
	require.NoError(t, apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_Q", appQ.ID, rawKey, pepper))

	app := fiber.New()
	pkMw := middleware.RequirePublishableKey(apiKeySvc)
	okHandler := func(c *fiber.Ctx) error { return c.Status(fiber.StatusOK).SendString("ok") }

	// A normal API route — NOT on the allowlist.
	app.Get("/v1/client/user/profile", pkMw, okHandler)
	app.Post("/v1/client/login", pkMw, okHandler)
	// Allowlisted redirect landings.
	app.Get("/v1/client/verify-email", pkMw, okHandler)
	app.Get("/v1/client/auth/magic-link/verify", pkMw, okHandler)
	app.Get("/v1/client/auth/social/:provider/callback", pkMw, okHandler)
	app.Get("/v1/oauth/authorize", pkMw, okHandler)
	// Allowlisted path, non-GET method.
	app.Post("/v1/client/verify-email", pkMw, okHandler)

	// --- The fallback is REMOVED on ordinary routes -------------------------

	// 1. A VALID key in ?publishable_key= on a non-allowlisted GET -> 401.
	//    This is the core M6 assertion: a key that would have been accepted
	//    before is now rejected because it arrived in the query string.
	req := httptest.NewRequest("GET", "/v1/client/user/profile?publishable_key="+rawKey, nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"publishable_key query param must not authenticate a non-redirect route")

	// 2. Same for the short ?pk= alias.
	req = httptest.NewRequest("GET", "/v1/client/user/profile?pk="+rawKey, nil)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"pk query param must not authenticate a non-redirect route")

	// 3. Same on a POST route — API calls always have a header available.
	req = httptest.NewRequest("POST", "/v1/client/login?publishable_key="+rawKey, nil)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"query fallback must not apply to POST routes")

	// 4. The header still works on those same routes — the change scopes the
	//    fallback, it does not break header auth.
	req = httptest.NewRequest("GET", "/v1/client/user/profile", nil)
	req.Header.Set("X-Authn-Publishable-Key", rawKey)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// --- The fallback is PRESERVED on redirect landings ---------------------

	for _, path := range []string{
		"/v1/client/verify-email?token=abc&publishable_key=" + rawKey,
		"/v1/client/auth/magic-link/verify?token=abc&pk=" + rawKey,
		"/v1/client/auth/social/google/callback?code=abc&publishable_key=" + rawKey,
		"/v1/oauth/authorize?response_type=code&pk=" + rawKey,
	} {
		req = httptest.NewRequest("GET", path, nil)
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"redirect landing %s must still accept the key from the query string", path)
	}

	// 5. The allowlist is keyed on method as well as path: POSTing to an
	//    allowlisted path does not inherit the exemption.
	req = httptest.NewRequest("POST", "/v1/client/verify-email?publishable_key="+rawKey, nil)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"query fallback is GET-only even on an allowlisted path")

	// 6. An invalid key in the query on an allowlisted route is still rejected —
	//    the exemption changes where the key may be read from, never whether it
	//    is validated.
	req = httptest.NewRequest("GET", "/v1/client/verify-email?publishable_key=pk_test_bogus_key_value_here", nil)
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
