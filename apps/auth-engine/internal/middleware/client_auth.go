/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/client_auth.go
 * Tier: HTTP Middleware Layer / Client Session Authentication
 *
 * End-user session authentication for the authenticated half of /v1/client.
 *
 * Verifies the caller's JWT access token, then installs the identity it carries
 * on the privacy context and the request locals so downstream handlers and ORM
 * hooks operate as that user, in that tenant, in that environment.
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

// extractAccessToken resolves an end-user's access token in the canonical
// precedence order: the authn_access_token cookie, then the access_token cookie,
// then the Authorization: Bearer header. It returns "" when the request carries
// none of them.
//
// This is the single source of truth for where an end-user's access token comes
// from, and every middleware that inspects one MUST route through it —
// RequireClientAuth to authenticate, PreventImpersonatedMutations to decide
// whether the session is impersonated. If the two disagreed on precedence, a
// session authenticated by cookie would be invisible to the guard and visible to
// the authenticator, and the impersonation restriction would silently not apply.
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

// RequireClientAuth returns a Fiber middleware that admits only callers holding
// a valid, unexpired JWT access token, verified against signingSecret.
//
// On success it installs the token's tenant and environment on the privacy
// context, and the subject, tenant and environment on the request locals. It
// answers 401 when no token is present and 401 when the token fails
// verification, distinguished by error code so a client can tell "sign in" from
// "refresh your session".
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

		// Both spellings of the user-ID local are set: handlers across the engine
		// read one or the other, and a missing identity reads as an anonymous
		// caller rather than an error.
		c.Locals("userID", claims.Sub)
		c.Locals("user_id", claims.Sub)
		c.Locals("tenant_id", claims.TenantID)
		c.Locals("environment", claims.Environment)

		return c.Next()
	}
}
