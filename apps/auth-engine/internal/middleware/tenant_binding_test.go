/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/tenant_binding_test.go
 * Tier: Internal Feature Package / Middleware Unit Tests
 *
 * Pins the two rules that bind a request's credentials to each other rather
 * than validating them in isolation: a session token must belong to the same
 * tenant as the API key it arrives with, and a browser origin must be one the
 * calling application registered.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorCode reads the machine-readable code out of an error envelope. Clients
// branch on that field, not on the prose, so it is what the tests assert.
func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var env struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(body, &env), "body was not an error envelope: %s", body)
	return env.Code
}

// TestTokenTenantMustMatchKeyTenant asserts that a session from one tenant
// cannot be presented alongside another tenant's publishable key.
//
// Both credentials are individually valid in that situation, so nothing but a
// comparison catches it. The caller still acts as their own tenant, and no data
// crosses the boundary — but without the comparison an application cannot assume
// its users belong to its customer, which is the assumption behind per-tenant
// user counts, limits, and the isolation promise itself.
func TestTokenTenantMustMatchKeyTenant(t *testing.T) {
	const (
		pepper = "test_pepper_key_32_bytes_long_12345"
		secret = "test_signing_secret_32_bytes_long_abc"
	)

	factory, err := clientfactory.NewClientFactory("sqlite3", "file:tenant_binding_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeySvc := apikey.NewService(apiKeyRepo, pepper)

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tntA, err := client.Tenant.Create().SetID("tnt_match_A").SetName("Tenant A").SetSlug("match-a").Save(sysCtx)
	require.NoError(t, err)
	appA, err := client.Application.Create().SetID("app_match_A").SetTenantID(tntA.ID).SetName("App A").Save(sysCtx)
	require.NoError(t, err)
	rawKeyA := "pk_test_MATCHA234567890123456789012345678"
	require.NoError(t, apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_match_A", appA.ID, rawKeyA, pepper))

	tntB, err := client.Tenant.Create().SetID("tnt_match_B").SetName("Tenant B").SetSlug("match-b").Save(sysCtx)
	require.NoError(t, err)

	// Tokens for a user of each tenant. Only the tenant claim differs.
	tokenA, err := jwtpkg.IssueAccessToken("usr_a", tntA.ID, "test", "a@example.com", "A", "", secret, time.Hour)
	require.NoError(t, err)
	tokenB, err := jwtpkg.IssueAccessToken("usr_b", tntB.ID, "test", "b@example.com", "B", "", secret, time.Hour)
	require.NoError(t, err)

	// The production arrangement on /v1/client: the key resolves the tenant,
	// then the token authenticates the user within it.
	app := fiber.New()
	app.Get("/v1/client/me",
		middleware.RequirePublishableKey(apiKeySvc),
		middleware.RequireClientAuth(secret, nil),
		func(c *fiber.Ctx) error {
			p, _ := privacy.FromContext(c.UserContext())
			return c.JSON(fiber.Map{
				"tenant_id":      p.TenantID,
				"application_id": p.ApplicationID,
				"user_id":        c.Locals("user_id"),
			})
		})

	// 1. Tenant B's token with Tenant A's key -> 401 tenant_mismatch.
	req := httptest.NewRequest("GET", "/v1/client/me", nil)
	req.Header.Set("X-Authn-Publishable-Key", rawKeyA)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a token from another tenant must not be accepted with this tenant's key")
	assert.Equal(t, "tenant_mismatch", errorCode(t, resp),
		"the code must name the actual mistake so an integrator can act on it")

	// 2. Tenant A's own token with Tenant A's key -> 200, and the application
	//    the key resolved survives into the privacy context.
	req = httptest.NewRequest("GET", "/v1/client/me", nil)
	req.Header.Set("X-Authn-Publishable-Key", rawKeyA)
	req.Header.Set("Authorization", "Bearer "+tokenA)
	resp, err = app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var got struct {
		TenantID      string `json:"tenant_id"`
		ApplicationID string `json:"application_id"`
		UserID        string `json:"user_id"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, tntA.ID, got.TenantID)
	assert.Equal(t, appA.ID, got.ApplicationID,
		"the application resolved by the key must not be dropped when the token is verified")
	assert.Equal(t, "usr_a", got.UserID)

	// 3. With no key middleware ahead of it, the token is the only tenant
	//    authority and is accepted on its own: the rule compares two credentials
	//    when both are present, and never requires a key that a route did not.
	solo := fiber.New()
	solo.Get("/v1/client/solo", middleware.RequireClientAuth(secret, nil), func(c *fiber.Ctx) error {
		return c.SendString(middleware.GetTenantID(c))
	})
	req = httptest.NewRequest("GET", "/v1/client/solo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	resp, err = solo.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, tntB.ID, string(body))
}

// TestPerApplicationOriginAllowlist asserts that an application's own origin
// list is enforced once its publishable key resolves it.
//
// A publishable key is public by design — it ships in a browser bundle — so the
// deployment-wide CORS gate is not enough on its own: it runs before any key is
// read and cannot tell one customer's application from another's.
func TestPerApplicationOriginAllowlist(t *testing.T) {
	const pepper = "test_pepper_key_32_bytes_long_12345"

	factory, err := clientfactory.NewClientFactory("sqlite3", "file:app_origin_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeySvc := apikey.NewService(apiKeyRepo, pepper)

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tnt, err := client.Tenant.Create().SetID("tnt_origin").SetName("Origin Co").SetSlug("origin-co").Save(sysCtx)
	require.NoError(t, err)

	// One application with a configured allowlist, one without.
	guarded, err := client.Application.Create().
		SetID("app_guarded").SetTenantID(tnt.ID).SetName("Guarded").
		SetAllowedCorsOrigins([]string{"https://app.example.com", "https://Admin.Example.com/"}).
		Save(sysCtx)
	require.NoError(t, err)
	open, err := client.Application.Create().
		SetID("app_open").SetTenantID(tnt.ID).SetName("Open").
		Save(sysCtx)
	require.NoError(t, err)

	rawGuarded := "pk_test_GUARDED34567890123456789012345678"
	rawOpen := "pk_test_OPENKEY34567890123456789012345678"
	require.NoError(t, apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_guarded", guarded.ID, rawGuarded, pepper))
	require.NoError(t, apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_open", open.ID, rawOpen, pepper))

	app := fiber.New()
	app.Get("/v1/client/ping", middleware.RequirePublishableKey(apiKeySvc), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	call := func(key, origin string) *http.Response {
		t.Helper()
		req := httptest.NewRequest("GET", "/v1/client/ping", nil)
		req.Header.Set("X-Authn-Publishable-Key", key)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := app.Test(req)
		require.NoError(t, err)
		return resp
	}

	// 1. A registered origin passes.
	assert.Equal(t, http.StatusOK, call(rawGuarded, "https://app.example.com").StatusCode)

	// 2. Case and a trailing slash are normalized on both sides, so a stored
	//    "https://Admin.Example.com/" matches the origin a browser actually sends.
	assert.Equal(t, http.StatusOK, call(rawGuarded, "https://admin.example.com").StatusCode)

	// 3. An unregistered origin is refused before the handler runs — the point
	//    of enforcing here rather than relying on the browser, which would let
	//    the request execute and only then withhold the response.
	resp := call(rawGuarded, "https://evil.example.com")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "origin_not_allowed", errorCode(t, resp))

	// 4. A near miss is still a miss: matching is exact, with no suffix or
	//    subdomain matching that "app.example.com.evil.com" could exploit.
	assert.Equal(t, http.StatusForbidden, call(rawGuarded, "https://app.example.com.evil.com").StatusCode)
	assert.Equal(t, http.StatusForbidden, call(rawGuarded, "http://app.example.com").StatusCode,
		"scheme is part of the origin: http must not satisfy an https entry")

	// 5. No Origin header at all — a server-to-server call, a mobile SDK, an
	//    emailed-link landing. An origin allowlist does not govern these.
	assert.Equal(t, http.StatusOK, call(rawGuarded, "").StatusCode)

	// 6. An empty allowlist means "not configured", so an application that never
	//    registered an origin is not governed by one. A default-deny here would
	//    instead make the field mandatory for every deployment.
	assert.Equal(t, http.StatusOK, call(rawOpen, "https://anywhere.example.com").StatusCode)
}
