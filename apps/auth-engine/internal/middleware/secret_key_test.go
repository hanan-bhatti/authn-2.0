/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/secret_key_test.go
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

func TestRequireSecretKeyMiddleware(t *testing.T) {
	pepper := "test_pepper_key_32_bytes_long_12345"
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:sk_middleware_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeySvc := apikey.NewService(apiKeyRepo, pepper)

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tnt, err := client.Tenant.Create().SetID("tnt_sk_test").SetName("SK Test Tenant").SetSlug("sk-test").Save(sysCtx)
	require.NoError(t, err)

	appEntity, err := client.Application.Create().SetID("app_sk_test").SetTenantID(tnt.ID).SetName("SK App").Save(sysCtx)
	require.NoError(t, err)

	rawPK := "pk_test_PublishableKey123456789012"
	err = apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_pk", appEntity.ID, rawPK, pepper)
	require.NoError(t, err)

	genSK, err := apikey.GenerateApiKey(apikey.TypeSecret, "test", pepper)
	require.NoError(t, err)
	_, err = apiKeyRepo.CreateApiKey(sysCtx, "key_sk", appEntity.ID, "Admin Key", apikey.TypeSecret, genSK.Prefix, genSK.KeyHash, "test", nil)
	require.NoError(t, err)

	app := fiber.New()
	skMw := middleware.RequireSecretKey(apiKeySvc)

	app.Get("/v1/admin/test", skMw, func(c *fiber.Ctx) error {
		p, ok := privacy.FromContext(c.UserContext())
		if !ok {
			return c.Status(fiber.StatusInternalServerError).SendString("no privacy context")
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"tenant_id":   p.TenantID,
			"environment": p.Environment,
		})
	})

	// 1. Request with NO Authorization header -> 401 Unauthorized
	req1 := httptest.NewRequest("GET", "/v1/admin/test", nil)
	resp1, err := app.Test(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp1.StatusCode)

	// 2. Request with Publishable Key -> MUST BE REJECTED with 401 Unauthorized
	req2 := httptest.NewRequest("GET", "/v1/admin/test", nil)
	req2.Header.Set("Authorization", "Bearer "+rawPK)
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// 3. Request with Secret Key -> 200 OK
	req3 := httptest.NewRequest("GET", "/v1/admin/test", nil)
	req3.Header.Set("Authorization", "Bearer "+genSK.RawKey)
	resp3, err := app.Test(req3)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)
}
