/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/console_auth.go
 * Tier: HTTP Middleware Layer / Console Session Authentication
 *
 * Console-only authentication for the Authn developer console.
 *
 * Console operators sign in through the same /v1/client/auth/login endpoint as any
 * other user and call admin routes with the resulting JWT, so no sk_ secret key
 * is ever embedded in a browser. This middleware is the JWT-only counterpart to
 * RequireSecretKey; RequireAdminAuth accepts either credential on routes that
 * serve both console and backend callers.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// RequireConsoleAuth returns a Fiber middleware that admits only a valid JWT
// access token whose role claim is "tenant_admin", verified against
// signingSecret. The token is read from the authn_access_token cookie, then the
// access_token cookie, then Authorization: Bearer.
//
// It answers 401 for a missing or unverifiable token and 403 for a valid
// end-user token without the role, so an ordinary session can never reach an
// admin route by being merely authenticated. On success the token's tenant and
// environment go onto the privacy context, scoping every downstream ORM query,
// and the operator's identity onto the request locals in the same shape the
// secret-key middleware uses.
func RequireConsoleAuth(signingSecret string) fiber.Handler {
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
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"console session required: provide Authorization: Bearer <jwt> or authn_access_token cookie")
		}

		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"invalid or expired console session token")
		}

		if claims.Role != "tenant_admin" {
			return httperr.Forbidden(c, httperr.CodeTenantAdminRequired,
				"forbidden: tenant_admin role required to access this resource")
		}

		privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, "", claims.Environment)
		c.SetUserContext(privacyCtx)

		c.Locals("tenant_id", claims.TenantID)
		c.Locals("environment", claims.Environment)
		c.Locals("console_user_id", claims.Sub)
		c.Locals("console_user_email", claims.Email)

		return c.Next()
	}
}
