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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// extractAccessToken resolves the caller's access token using the canonical
// precedence for end-user sessions: the authn_access_token cookie, then the
// access_token cookie, then the Authorization: Bearer header.
//
// This is the SINGLE source of truth for "where does an end-user's access token
// come from". Both RequireClientAuth and PreventImpersonatedMutations MUST route
// through it. When the two disagreed — the guard reading only the Authorization
// header while auth also honored cookies — a cookie-authed impersonation session
// slipped straight past the read-only guard (audit finding H6).
func extractAccessToken(c *fiber.Ctx) string {
	if tok := c.Cookies("authn_access_token"); tok != "" {
		return tok
	}
	if tok := c.Cookies("access_token"); tok != "" {
		return tok
	}
	authHeader := c.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	return ""
}

// RequireClientAuth returns a Fiber middleware enforcing valid JWT access token authentication for end-users.
func RequireClientAuth(signingSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenStr := extractAccessToken(c)

		if strings.TrimSpace(tokenStr) == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"authentication required: provide Authorization: Bearer <access_token>")
		}

		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"invalid or expired access token")
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
