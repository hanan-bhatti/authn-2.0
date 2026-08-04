/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/secret_key.go
 * Tier: HTTP Middleware Layer / Secret Key Admin Authentication
 *
 * Description: Fiber HTTP middleware enforcing valid, unrevoked Secret Admin API key (`sk_test_...` / `sk_live_...`)
 *              via Authorization: Bearer header or X-Authn-Secret-Key header.
 *              Automatically populates PrivacyContext (tenant_id + environment) for ORM boundary enforcement.
 *              MUST NEVER accept publishable keys (`pk_...`).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// RequireSecretKey returns a Fiber middleware enforcing valid secret admin key authentication.
func RequireSecretKey(apiKeyService *apikey.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Extract secret key from Authorization Bearer header or X-Authn-Secret-Key header
		rawKey := c.Get("X-Authn-Secret-Key")
		if rawKey == "" {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				rawKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		rawKey = strings.TrimSpace(rawKey)
		if rawKey == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing secret admin API key in Authorization Bearer or X-Authn-Secret-Key header",
			})
		}

		// 2. Validate key against database records (MUST be type 'secret')
		key, app, err := apiKeyService.ValidateKey(c.UserContext(), rawKey, apikey.TypeSecret)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid, expired, revoked, or non-secret API key",
			})
		}

		// 3. Inject resolved TenantID, ApplicationID, and Environment mode into PrivacyContext
		envStr := string(key.Environment)
		privacyCtx := privacy.NewContext(c.UserContext(), app.TenantID, app.ID, envStr)
		c.SetUserContext(privacyCtx)

		// 4. Store resolved metadata on Fiber request locals
		c.Locals("tenant_id", app.TenantID)
		c.Locals("application_id", app.ID)
		c.Locals("environment", envStr)
		c.Locals("api_key_id", key.ID)

		return c.Next()
	}
}
