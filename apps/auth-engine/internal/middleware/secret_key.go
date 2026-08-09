/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/secret_key.go
 * Tier: HTTP Middleware Layer / Secret Key Authentication
 *
 * Secret API key authentication for backend-to-backend admin calls.
 *
 * A secret key (sk_test_... / sk_live_...) authorises the full admin surface for
 * one application, so it belongs only in a server the tenant controls. The key
 * type is checked on every request: a publishable key, which ships in browser
 * bundles and is public by design, must never authenticate here.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// RequireSecretKey returns a Fiber middleware that admits only requests bearing
// a valid, unrevoked secret API key, read from X-Authn-Secret-Key or
// Authorization: Bearer.
//
// On success it installs the key's tenant, application and environment on the
// privacy context — which the ORM hooks read to scope every query — and on the
// request locals, along with the key ID for audit attribution. It answers 401
// when the key is missing, and 401 when it is invalid, expired, revoked, or not
// of the secret type; the type check is enforced by ValidateKey's type argument,
// not by inspecting the prefix.
func RequireSecretKey(apiKeyService *apikey.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		rawKey := c.Get("X-Authn-Secret-Key")
		if rawKey == "" {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				rawKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		rawKey = strings.TrimSpace(rawKey)
		if rawKey == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"missing secret admin API key in Authorization Bearer or X-Authn-Secret-Key header")
		}

		key, app, err := apiKeyService.ValidateKey(c.UserContext(), rawKey, apikey.TypeSecret)
		if err != nil {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"invalid, expired, revoked, or non-secret API key")
		}

		envStr := string(key.Environment)
		privacyCtx := privacy.NewContext(c.UserContext(), app.TenantID, app.ID, envStr)
		c.SetUserContext(privacyCtx)

		c.Locals("tenant_id", app.TenantID)
		c.Locals("application_id", app.ID)
		c.Locals("environment", envStr)
		c.Locals("api_key_id", key.ID)

		return c.Next()
	}
}
