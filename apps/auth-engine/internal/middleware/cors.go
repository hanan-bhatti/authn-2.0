/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/cors.go
 * Tier: HTTP Middleware Layer
 *
 * Cross-Origin Resource Sharing policy.
 *
 * A browser will not let a page on one origin read a response from another
 * unless the server opts in with CORS headers. This middleware decides which
 * origins are granted that permission.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

// CORS returns a Fiber middleware enforcing the configured cross-origin policy.
//
// Origins come from CORS_ALLOWED_ORIGINS and are matched exactly, so only a
// listed origin is echoed back in Access-Control-Allow-Origin and a request
// from anywhere else is blocked by the browser.
//
// The alternative — reflecting whatever Origin header arrives — combined with
// credentials would let any site a signed-in user visits call this API with
// their cookies attached and read the replies. config.Validate refuses that
// combination at startup, and this middleware never reflects an unlisted origin.
//
// This is the outer bound for the whole deployment, not the per-customer policy.
// It runs before any API key is read, so it cannot know which application is
// calling; each application's own allowlist is enforced once the key resolves it,
// in originAllowedForApplication. A request must satisfy both, which is what
// stops one tenant's settings from widening the deployment's exposure.
func CORS(cfg *config.Config) fiber.Handler {
	allowed := make(map[string]struct{}, len(cfg.CORSAllowedOrigins))
	wildcard := false
	for _, origin := range cfg.CORSAllowedOrigins {
		if origin == "*" {
			wildcard = true
			continue
		}
		allowed[NormalizeOrigin(origin)] = struct{}{}
	}

	return cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			// A wildcard only reaches this point when credentials are disabled,
			// because Validate rejects the pairing before the server starts.
			if wildcard {
				return true
			}
			_, ok := allowed[NormalizeOrigin(origin)]
			return ok
		},
		AllowMethods:     strings.Join(cfg.CORSAllowedMethods, ","),
		AllowHeaders:     strings.Join(cfg.CORSAllowedHeaders, ","),
		AllowCredentials: cfg.CORSAllowCredentials,
		MaxAge:           int(cfg.CORSMaxAge.Seconds()),
	})
}

// NormalizeOrigin lowercases an origin and drops any trailing slash, so that
// "https://App.Example.com/" and "https://app.example.com" compare equal.
// Origin comparison is otherwise exact: no wildcards, no suffix matching.
//
// Exported because per-application origin storage must normalize with the very
// same function the request-path matcher uses. A stored origin normalized one
// way and matched another would silently never match, and an application would
// reject a browser it was configured to allow.
func NormalizeOrigin(origin string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(origin), "/"))
}

// ValidateOrigin reports whether raw is a usable CORS origin and returns its
// normalized form.
//
// A CORS origin is a scheme, host and optional port — never a path, query or
// fragment. The browser sends exactly that in the Origin header, so anything
// carrying more cannot match one and is a configuration mistake worth catching
// at write time rather than discovering as a login that silently fails to
// persist. "*" is accepted only as a deployment-wide setting, never per
// application, so it is refused here.
func ValidateOrigin(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "*" {
		return "", false
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", false
	}
	// A scheme and host are mandatory; a path, query or fragment, or embedded
	// credentials, mean the value is a URL rather than an origin.
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Host == "" || u.User != nil {
		return "", false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if path := strings.TrimRight(u.Path, "/"); path != "" {
		return "", false
	}

	return NormalizeOrigin(trimmed), true
}
