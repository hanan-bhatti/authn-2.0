/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/cors_test.go
 * Tier: HTTP Middleware Layer / Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// corsTestConfig is a deployment allowing one origin with credentials, the shape
// a browser-facing deployment actually runs.
func corsTestConfig() *config.Config {
	return &config.Config{
		CORSAllowedOrigins:   []string{"https://app.example.com"},
		CORSAllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		CORSAllowedHeaders:   []string{"Content-Type", "Authorization", "X-Authn-Publishable-Key"},
		CORSAllowCredentials: true,
	}
}

// TestCORSExposesTheResponseHeadersClientsRead checks that the engine's own
// response headers are readable by a cross-origin caller.
//
// A browser hides every response header from a cross-origin script except a
// short safelist, so a header the engine sets but does not expose reads back as
// absent — with no error to say why. Retry-After carries the server's own backoff
// interval, and a client that cannot read it can only guess how long to wait;
// X-Authn-Degraded-Mode tells a client that Redis is down. Both are read by the
// browser SDK, so neither works unless it is named in the exposed list.
func TestCORSExposesTheResponseHeadersClientsRead(t *testing.T) {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(middleware.CORS(corsTestConfig()))
	app.Get("/probe", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("GET", "/probe", nil)
	req.Header.Set("Origin", "https://app.example.com")

	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	exposed := resp.Header.Get("Access-Control-Expose-Headers")
	for _, want := range []string{"X-Authn-Degraded-Mode", "Retry-After"} {
		assert.Contains(t, exposed, want,
			"%s is set by the engine and read by clients, so it must be exposed cross-origin", want)
	}
}

// TestCORSPreflightAdmitsTheConfiguredHeaders checks that a preflight answer
// carries the configured request headers, since a browser drops any header the
// answer omits before the real request is ever sent.
func TestCORSPreflightAdmitsTheConfiguredHeaders(t *testing.T) {
	cfg := corsTestConfig()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(middleware.CORS(cfg))
	app.Post("/probe", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("OPTIONS", "/probe", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "X-Authn-Publishable-Key")

	resp, err := app.Test(req)
	require.NoError(t, err)

	allowed := strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers"))
	for _, want := range cfg.CORSAllowedHeaders {
		assert.Contains(t, allowed, strings.ToLower(want))
	}
	assert.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
}

// TestCORSDoesNotAnswerAnUnlistedOrigin checks that an origin outside the
// allowlist is never echoed back. Reflecting an arbitrary origin alongside
// credentials is what would let any site a signed-in user visits call this API
// with their cookies attached and read the reply.
func TestCORSDoesNotAnswerAnUnlistedOrigin(t *testing.T) {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(middleware.CORS(corsTestConfig()))
	app.Get("/probe", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("GET", "/probe", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.NotEqual(t, "https://evil.example.com", resp.Header.Get("Access-Control-Allow-Origin"),
		"an unlisted origin must never be reflected")
}
