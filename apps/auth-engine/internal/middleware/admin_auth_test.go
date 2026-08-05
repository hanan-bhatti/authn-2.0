/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/admin_auth_test.go
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
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mock2FAValidator struct {
	counts map[string]int
}

func (m *mock2FAValidator) CountActivePrimary2FAMethods(ctx context.Context, userID string) (int, error) {
	if count, ok := m.counts[userID]; ok {
		return count, nil
	}
	return 0, nil
}

func TestRequireAdminAuthMiddleware(t *testing.T) {
	pepper := "test_pepper_key_32_bytes_long_12345"
	secretKey := "test_jwt_secret_key_32_bytes_long"
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:admin_auth_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeySvc := apikey.NewService(apiKeyRepo, pepper)

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tntA, err := client.Tenant.Create().SetID("tnt_adminA").SetName("Tenant Admin A").SetSlug("tnt-admin-a").Save(sysCtx)
	require.NoError(t, err)

	appA, err := client.Application.Create().SetID("app_adminA").SetTenantID(tntA.ID).SetName("App Admin A").Save(sysCtx)
	require.NoError(t, err)

	rawSK := "sk_test_ADMIN1234567890123456789012345678"
	err = apiKeyRepo.EnsureDefaultApiKeyExists(sysCtx, "key_sk_A", appA.ID, rawSK, pepper)
	require.NoError(t, err)

	mockValidator := &mock2FAValidator{
		counts: map[string]int{
			"usr_admin_with_2fa":    1,
			"usr_admin_without_2fa": 0,
		},
	}

	app := fiber.New()
	adminMw := middleware.RequireAdminAuth(apiKeySvc, secretKey, mockValidator)

	app.Get("/v1/admin/protected", adminMw, func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status": "ok",
		})
	})

	// 1. Missing Authorization Header -> 401 Unauthorized
	req1 := httptest.NewRequest("GET", "/v1/admin/protected", nil)
	resp1, err := app.Test(req1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp1.StatusCode)

	// 2. Secret Key (sk_...) -> 200 OK (Bypasses user 2FA check)
	req2 := httptest.NewRequest("GET", "/v1/admin/protected", nil)
	req2.Header.Set("Authorization", "Bearer "+rawSK)
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// 3. Admin Console JWT WITH 2FA -> 200 OK
	adminJWTWith2FA, err := jwtpkg.IssueAccessToken("usr_admin_with_2fa", "tnt_adminA", "test", "admin@example.com", "Admin User", "tenant_admin", secretKey)
	require.NoError(t, err)

	req3 := httptest.NewRequest("GET", "/v1/admin/protected", nil)
	req3.Header.Set("Authorization", "Bearer "+adminJWTWith2FA)
	resp3, err := app.Test(req3)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	// 4. Admin Console JWT WITHOUT 2FA -> 403 Forbidden (admin_2fa_required)
	adminJWTNo2FA, err := jwtpkg.IssueAccessToken("usr_admin_without_2fa", "tnt_adminA", "test", "no2fa@example.com", "No 2FA Admin", "tenant_admin", secretKey)
	require.NoError(t, err)

	req4 := httptest.NewRequest("GET", "/v1/admin/protected", nil)
	req4.Header.Set("Authorization", "Bearer "+adminJWTNo2FA)
	resp4, err := app.Test(req4)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp4.StatusCode)

	// 5. Regular User JWT (role != tenant_admin) -> 403 Forbidden
	userJWT, err := jwtpkg.IssueAccessToken("usr_regular", "tnt_adminA", "test", "user@example.com", "Regular User", "", secretKey)
	require.NoError(t, err)

	req5 := httptest.NewRequest("GET", "/v1/admin/protected", nil)
	req5.Header.Set("Authorization", "Bearer "+userJWT)
	resp5, err := app.Test(req5)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp5.StatusCode)
}
