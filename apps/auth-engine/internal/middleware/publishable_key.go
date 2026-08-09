/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/publishable_key.go
 * Tier: HTTP Middleware Layer / API Key Authentication
 *
 * Publishable API key authentication for public client routes.
 *
 * A publishable key (pk_test_... / pk_live_...) identifies the calling
 * application and resolves the tenant and environment that scope every
 * downstream ORM query. It is low-sensitivity by design — it ships in browser
 * bundles — but it is still the value that binds a request to a tenant, so it is
 * required, validated, and never inferred.
 *
 * The X-Authn-Publishable-Key header is the only transport, except on a closed
 * allowlist of redirect-landing GET routes where the caller physically cannot
 * set a header (see pkQueryFallbackRoutes).
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

// pkQueryFallbackRoute names one route permitted to carry the publishable key in
// the query string.
type pkQueryFallbackRoute struct {
	// prefix is the leading portion of the path. When suffix is empty it is the
	// whole path, matched exactly.
	prefix string
	// suffix, when non-empty, marks a route with a variable segment in the middle
	// (/auth/social/:provider/callback). The path must then start with prefix and
	// end with suffix.
	suffix string
}

// pkQueryFallbackRoutes is the closed allowlist of routes that may supply the
// publishable key as ?publishable_key= or ?pk= instead of a header.
//
// A key in the query string lands in access logs, browser history, and the
// Referer header of every outbound link on the page it loads. The header costs
// nothing to set, so the fallback is confined to the requests that cannot set
// one: a route qualifies ONLY if it is (a) a GET, (b) reached by top-level
// browser navigation rather than fetch or XHR, and (c) behind
// RequirePublishableKey. Non-GET methods are refused outright, which keeps the
// fallback unreachable from any API-style call that had a header available.
var pkQueryFallbackRoutes = []pkQueryFallbackRoute{
	// Emailed-link landings: the link is opened from a mail client, and no
	// JavaScript runs before the request is issued.
	{prefix: "/v1/client/verify-email"},
	{prefix: "/v1/client/auth/magic-link/verify"},
	{prefix: "/v1/client/user/email/verify"},
	{prefix: "/v1/client/user/recovery-email/verify"},

	// Social login: top-level navigation out to the identity provider, and the
	// provider's 302 back. The callback URL is registered verbatim in the
	// provider console and matched exactly, so no header can be attached to it.
	{prefix: "/v1/client/auth/social/", suffix: "/authorize"},
	{prefix: "/v1/client/auth/social/", suffix: "/callback"},

	// OAuth2 authorization endpoint: top-level browser navigation by definition.
	{prefix: "/v1/oauth/authorize"},
}

// allowsPublishableKeyInQuery reports whether (method, path) is on the
// redirect-landing allowlist. Non-GET methods are always false. Path comparison
// is case-insensitive and ignores a single trailing slash.
func allowsPublishableKeyInQuery(method, path string) bool {
	if strings.ToUpper(method) != fiber.MethodGet {
		return false
	}

	path = strings.ToLower(strings.TrimRight(path, "/"))
	for _, r := range pkQueryFallbackRoutes {
		prefix := strings.ToLower(strings.TrimRight(r.prefix, "/"))
		if r.suffix == "" {
			if path == prefix {
				return true
			}
			continue
		}
		if strings.HasPrefix(path, prefix+"/") && strings.HasSuffix(path, strings.ToLower(r.suffix)) {
			return true
		}
	}
	return false
}

// RequirePublishableKey returns a Fiber middleware that admits only requests
// carrying a valid, unrevoked publishable key.
//
// On success it resolves the key's application and installs the tenant,
// application and environment on both the privacy context — which the ORM hooks
// read to scope every query — and the Fiber locals. It answers 401 when the key
// is absent, and 401 when it is invalid, expired, revoked, or of the wrong type;
// the two are distinguished by message only, since neither should tell an
// unauthenticated caller which keys exist.
func RequirePublishableKey(apiKeyService *apikey.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		rawKey := c.Get("X-Authn-Publishable-Key")
		if rawKey == "" && allowsPublishableKeyInQuery(c.Method(), c.Path()) {
			rawKey = c.Query("publishable_key")
			if rawKey == "" {
				rawKey = c.Query("pk")
			}
		}

		rawKey = strings.TrimSpace(rawKey)
		if rawKey == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"missing publishable API key in X-Authn-Publishable-Key header")
		}

		// The type argument is what stops a secret key being accepted here.
		key, app, err := apiKeyService.ValidateKey(c.UserContext(), rawKey, apikey.TypePublishable)
		if err != nil {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"invalid, expired, or revoked publishable API key")
		}

		envStr := string(key.Environment)
		privacyCtx := privacy.NewContext(c.UserContext(), app.TenantID, app.ID, envStr)
		c.SetUserContext(privacyCtx)

		c.Locals("tenant_id", app.TenantID)
		c.Locals("application_id", app.ID)
		c.Locals("environment", envStr)

		return c.Next()
	}
}
