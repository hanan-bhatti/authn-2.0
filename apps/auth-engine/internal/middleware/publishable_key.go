/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/publishable_key.go
 * Tier: HTTP Middleware Layer / API Key Security
 *
 * Description: Fiber HTTP middleware enforcing valid, unrevoked Publishable API key (`pk_test_...` / `pk_live_...`)
 *              via X-Authn-Publishable-Key header. Automatically populates PrivacyContext (tenant_id + environment)
 *              for ORM privacy hook enforcement.
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

// RequirePublishableKey returns a Fiber middleware enforcing valid publishable key authentication.
func RequirePublishableKey(apiKeyService *apikey.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Extract publishable key from header or query param fallback
		rawKey := c.Get("X-Authn-Publishable-Key")
		if rawKey == "" {
			rawKey = c.Query("publishable_key")
		}
		if rawKey == "" {
			rawKey = c.Query("pk")
		}

		rawKey = strings.TrimSpace(rawKey)
		if rawKey == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing publishable API key in X-Authn-Publishable-Key header",
			})
		}

		// 2. Validate key against database records (type must be 'publishable')
		key, app, err := apiKeyService.ValidateKey(c.UserContext(), rawKey, apikey.TypePublishable)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid, expired, or revoked publishable API key",
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

		return c.Next()
	}
}
