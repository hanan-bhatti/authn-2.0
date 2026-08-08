/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/publishable_key.go
 * Tier: HTTP Middleware Layer / API Key Security
 *
 * Description: Fiber HTTP middleware enforcing valid, unrevoked Publishable API key (`pk_test_...` / `pk_live_...`)
 *              via X-Authn-Publishable-Key header. Automatically populates PrivacyContext (tenant_id + environment)
 *              for ORM privacy hook enforcement.
 *
 *              The header is the ONLY accepted transport except on a closed allowlist of
 *              redirect-landing GET routes (see pkQueryFallbackRoutes), where the caller is a
 *              browser following a 302 or an emailed link and physically cannot set a header.
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
// the query string. prefix is matched against the normalized request path; when
// suffix is non-empty the route has a variable segment in the middle (e.g.
// /auth/social/:provider/callback) and the path must start with prefix and end
// with suffix.
type pkQueryFallbackRoute struct {
	prefix string
	suffix string
}

// pkQueryFallbackRoutes is the closed allowlist of routes that may supply the
// publishable key as ?publishable_key= / ?pk= instead of a header.
//
// Audit finding M6: the fallback used to apply to EVERY route, which put the key
// into access logs, browser history, and the Referer header of any outbound link
// on the landing page — on POST endpoints that had a perfectly good header
// available. Publishable keys are low-sensitivity by design, but there is no
// reason to broadcast one on a request that could have sent a header.
//
// Every entry below is a GET that a browser arrives at by redirect or by clicking
// an emailed link, where no JavaScript runs before the request and no header can
// be attached. Non-GET methods are rejected outright, so the fallback cannot be
// reached by any API-style call.
//
// A route belongs here ONLY if it is (a) a GET, (b) reached by top-level browser
// navigation rather than fetch/XHR, and (c) behind RequirePublishableKey.
var pkQueryFallbackRoutes = []pkQueryFallbackRoute{
	// Emailed-link landings: the link is opened from a mail client.
	{prefix: "/v1/client/verify-email"},
	{prefix: "/v1/client/auth/magic-link/verify"},
	{prefix: "/v1/client/user/email/verify"},
	{prefix: "/v1/client/user/recovery-email/verify"},

	// Social login: top-level navigation out to the IdP, and the IdP's 302 back.
	// The callback URL is registered verbatim in the provider console and is
	// matched exactly by the IdP, so a header can never be added to it.
	{prefix: "/v1/client/auth/social/", suffix: "/authorize"},
	{prefix: "/v1/client/auth/social/", suffix: "/callback"},

	// OAuth2 authorization endpoint: top-level browser navigation by definition.
	{prefix: "/v1/oauth/authorize"},
}

// allowsPublishableKeyInQuery reports whether (method, path) is on the redirect
// allowlist. Comparison is case-insensitive and ignores a trailing slash.
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

// RequirePublishableKey returns a Fiber middleware enforcing valid publishable key authentication.
func RequirePublishableKey(apiKeyService *apikey.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Extract publishable key. The header is the default and only
		// universally accepted transport; the query fallback is scoped to the
		// redirect-landing GET routes above (audit finding M6).
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

		// 2. Validate key against database records (type must be 'publishable')
		key, app, err := apiKeyService.ValidateKey(c.UserContext(), rawKey, apikey.TypePublishable)
		if err != nil {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"invalid, expired, or revoked publishable API key")
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
