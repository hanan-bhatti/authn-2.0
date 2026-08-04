/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/console_auth.go
 * Tier: HTTP Middleware Layer / Console Session Authentication
 *
 * Description: Fiber HTTP middleware for the Authn developer console.
 *              Accepts a valid JWT access token (issued by the normal login flow)
 *              where claims.Role == "tenant_admin". Injects PrivacyContext so all
 *              downstream ORM queries are scoped to the correct tenant.
 *
 *              This is the console alternative to RequireSecretKey — console admins
 *              log in with their email/password through the same /v1/client/login
 *              endpoint and use the resulting JWT to call admin routes, rather than
 *              embedding an sk_ key in the browser.
 *
 *              Full RBAC (FR-12) will replace the coarse "tenant_admin" role check
 *              with granular permission evaluation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// RequireConsoleAuth returns a Fiber middleware that accepts a JWT access token
// (from Authorization: Bearer or authn_access_token cookie) where the embedded
// role claim equals "tenant_admin". Used to protect /v1/tenant/* and /v1/admin/*
// routes when the caller is the Authn web console rather than a backend server
// using an sk_ key.
func RequireConsoleAuth(signingSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Extract token from cookie or Authorization Bearer header
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
				"error": "console session required: provide Authorization: Bearer <jwt> or authn_access_token cookie",
			})
		}

		// 2. Verify signature and expiration
		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired console session token",
			})
		}

		// 3. Enforce tenant_admin role — regular end-users are rejected here
		if claims.Role != "tenant_admin" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "forbidden: tenant_admin role required to access this resource",
			})
		}

		// 4. Inject PrivacyContext so all ORM queries are tenant-scoped
		privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, "", claims.Environment)
		c.SetUserContext(privacyCtx)

		// 5. Store resolved metadata on Fiber request locals (matches sk_ middleware shape)
		c.Locals("tenant_id", claims.TenantID)
		c.Locals("environment", claims.Environment)
		c.Locals("console_user_id", claims.Sub)
		c.Locals("console_user_email", claims.Email)

		return c.Next()
	}
}
