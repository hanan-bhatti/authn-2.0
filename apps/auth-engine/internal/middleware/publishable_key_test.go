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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/mattn/go-sqlite3"
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
