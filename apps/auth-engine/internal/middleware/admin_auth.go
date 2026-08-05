/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/admin_auth.go
 * Tier: HTTP Middleware Layer / Combined Admin Authentication
 *
 * Description: RequireAdminAuth is the unified middleware for all admin routes
 *              (/v1/tenant/*, /v1/admin/*). It accepts EITHER:
 *
 *              1. sk_... secret key  — Backend servers / SDKs send this in
 *                 Authorization: Bearer or X-Authn-Secret-Key header.
 *
 *              2. JWT with role=tenant_admin — The Authn web console logs in
 *                 via the normal /v1/client/login endpoint and sends the resulting
 *                 JWT as Authorization: Bearer from the browser (never stores sk_).
 *
 *              Detection is done by inspecting the raw header value before any
 *              middleware writes to the response — sk_ keys start with "sk_",
 *              JWTs start with "eyJ". This avoids the "write-before-fallback"
 *              problem that arises when two separate middlewares are chained.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Primary2FAValidator defines the interface for checking if a user has active primary 2FA.
type Primary2FAValidator interface {
	CountActivePrimary2FAMethods(ctx context.Context, userID string) (int, error)
}

// RequireAdminAuth returns a Fiber middleware that gates admin routes behind
// EITHER a valid sk_... secret key OR a JWT access token with role=tenant_admin.
// If a Primary2FAValidator is provided, console admin users without active 2FA are rejected.
//
// Callers:
//   - Backend servers / SDKs: Authorization: Bearer sk_test_... or X-Authn-Secret-Key: sk_...
//   - Authn web console:      Authorization: Bearer eyJ... (JWT from /v1/client/login)
func RequireAdminAuth(apiKeyService *apikey.Service, signingSecret string, validator ...Primary2FAValidator) fiber.Handler {
	var v Primary2FAValidator
	if len(validator) > 0 {
		v = validator[0]
	}

	return func(c *fiber.Ctx) error {
		// Extract the raw credential from the standard locations
		raw := strings.TrimSpace(c.Get("X-Authn-Secret-Key"))
		if raw == "" {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				raw = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			}
		}

		if raw == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "admin authentication required: provide Authorization: Bearer sk_... (backend) or Bearer <jwt> with tenant_admin role (console)",
			})
		}

		// Route 1: sk_... secret key (backend server / SDK path)
		if strings.HasPrefix(raw, "sk_") {
			key, app, err := apiKeyService.ValidateKey(c.UserContext(), raw, apikey.TypeSecret)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid, expired, or revoked secret key",
				})
			}
			envStr := string(key.Environment)
			privacyCtx := privacy.NewContext(c.UserContext(), app.TenantID, app.ID, envStr)
			c.SetUserContext(privacyCtx)
			c.Locals("tenant_id", app.TenantID)
			c.Locals("application_id", app.ID)
			c.Locals("environment", envStr)
			c.Locals("api_key_id", key.ID)
			c.Locals("admin_auth_method", "secret_key")
			return c.Next()
		}

		// Route 2: JWT access token (console browser path)
		// JWTs are base64url-encoded JSON and always start with "eyJ"
		if strings.HasPrefix(raw, "eyJ") {
			claims, err := jwtpkg.VerifyAccessToken(raw, signingSecret)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid or expired console session token",
				})
			}
			if claims.Role != "tenant_admin" {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "forbidden: tenant_admin role required — regular user JWTs cannot access admin routes",
				})
			}

			// Mandatory Admin 2FA enforcement
			if v != nil {
				count, err := v.CountActivePrimary2FAMethods(c.UserContext(), claims.Sub)
				if err == nil && count == 0 {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":      "admin 2FA required: administrator accounts must enroll in 2FA (TOTP or Passkey) before accessing admin features",
						"code":       "admin_2fa_required",
						"enroll_uri": "/v1/client/2fa/totp/enroll",
					})
				}
			}

			privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, "", claims.Environment)
			c.SetUserContext(privacyCtx)
			c.Locals("tenant_id", claims.TenantID)
			c.Locals("environment", claims.Environment)
			c.Locals("console_user_id", claims.Sub)
			c.Locals("console_user_email", claims.Email)
			c.Locals("admin_auth_method", "console_jwt")
			return c.Next()
		}

		// Unrecognised credential format
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unrecognised credential format: expected sk_... secret key or eyJ... JWT access token",
		})
	}
}

// GetTenantID extracts resolved tenant_id from Fiber context locals, defaulting to "tnt_default".
func GetTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return "tnt_default"
}
