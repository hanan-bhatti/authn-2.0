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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// ExtractAccessToken resolves an end-user's access token in the canonical
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
func ExtractAccessToken(c *fiber.Ctx) string {
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
//
// When RequirePublishableKey ran first — the normal arrangement on /v1/client —
// the token's tenant must equal the tenant the key resolved, or the request is
// refused with CodeTenantMismatch. Without that check a user of tenant B could
// present their own token alongside tenant A's publishable key and be admitted
// as an authenticated user of A's application. They would still act as B, so it
// leaks nothing, but an application could no longer assume its users belong to
// its customer, which is what user counts, per-tenant limits and the isolation
// promise all rest on.
func RequireClientAuth(signingSecret string, bl *tokenblocklist.Blocklist) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenStr := ExtractAccessToken(c)

		if strings.TrimSpace(tokenStr) == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"authentication required: provide Authorization: Bearer <access_token>")
		}

		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"invalid or expired access token")
		}

		// A token whose JTI appears in the blocklist was explicitly revoked —
		// most commonly via ExitImpersonation — and must not be admitted even
		// though its signature and expiry are still valid.
		if bl.IsBlocked(c.UserContext(), claims.Jti) {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"invalid or expired access token")
		}

		// A restriction placed on the account after this token was minted refuses
		// it too. Without this the token stays good for the rest of its lifetime,
		// so a ban would take up to one access-token TTL to be felt — long enough
		// for whatever it was placed to stop.
		if bl.IsUserTokenRefused(c.UserContext(), claims.Sub, claims.Iat) {
			return httperr.Send(c, fiber.StatusForbidden, httperr.CodeAccountDisabled,
				"This account is no longer permitted to access this application.")
		}

		// Empty means no key middleware preceded this one, so there is nothing to
		// compare against and the token is the only tenant authority.
		if keyTenant := GetTenantID(c); keyTenant != "" && keyTenant != claims.TenantID {
			return httperr.Unauthorized(c, httperr.CodeTenantMismatch,
				"this session belongs to a different tenant than the API key used for this request — "+
					"sign in again through this application, or check that the publishable key matches "+
					"the account the user signed into")
		}

		// The application, when a key resolved one, is carried through: the token
		// itself has no application claim, and dropping the ID here would erase
		// which application the request arrived through.
		appID, _ := c.Locals("application_id").(string)
		privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, appID, claims.Environment)
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
