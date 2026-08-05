/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/client_auth.go
 * Tier: HTTP Middleware Layer / Client Session Authentication
 *
 * Description: RequireClientAuth validates Bearer access tokens or cookies for authenticated
 *              end-user API endpoints (/v1/client/user/*).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// RequireClientAuth returns a Fiber middleware enforcing valid JWT access token authentication for end-users.
func RequireClientAuth(signingSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenStr := ""
		if tok := c.Cookies("authn_access_token"); tok != "" {
			tokenStr = tok
		} else if tok := c.Cookies("access_token"); tok != "" {
			tokenStr = tok
		} else {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if strings.TrimSpace(tokenStr) == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required: provide Authorization: Bearer <access_token>",
			})
		}

		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired access token",
			})
		}

		privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, "", claims.Environment)
		c.SetUserContext(privacyCtx)

		c.Locals("userID", claims.Sub)
		c.Locals("user_id", claims.Sub)
		c.Locals("tenant_id", claims.TenantID)
		c.Locals("environment", claims.Environment)

		return c.Next()
	}
}
