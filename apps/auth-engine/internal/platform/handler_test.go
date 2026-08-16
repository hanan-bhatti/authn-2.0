/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/platform/handler_test.go
 * Tier: Handler Unit Tests / Hosted Control Plane
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package platform

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterRoutesMountsNothingWithoutAGuard covers the OSS deployment, where
// no platform tenant is configured and the middleware is nil.
//
// Mounting these routes unguarded would expose tenant creation and API-key minting
// to anonymous callers, and Fiber would not stop it: a nil handler is accepted at
// registration and only dereferenced on the first request, so the mistake surfaces
// as a router panic under load rather than a status code in a test.
//
// The second half is what makes the first half meaningful. A test asserting 404
// would pass just as happily against a typo in the route path, so the same
// registration is repeated with a real guard to show the paths themselves resolve.
func TestRegisterRoutesMountsNothingWithoutAGuard(t *testing.T) {
	h := NewHandler(nil, nil, nil, "authn-console")

	probe := func(t *testing.T, app *fiber.App, method, path string) int {
		t.Helper()
		resp, err := app.Test(httptest.NewRequest(method, path, nil))
		require.NoError(t, err)
		return resp.StatusCode
	}

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/platform/tenants"},
		{http.MethodGet, "/v1/platform/tenants"},
	}

	unguarded := fiber.New()
	h.RegisterRoutes(unguarded, nil)
	for _, r := range routes {
		assert.Equal(t, http.StatusNotFound, probe(t, unguarded, r.method, r.path),
			"%s %s must not be reachable without a guard", r.method, r.path)
	}

	// The same paths, behind a guard that refuses everyone: 401 rather than 404
	// proves the registration above was skipped by the nil check and not missed
	// because the paths were wrong.
	guarded := fiber.New()
	h.RegisterRoutes(guarded, func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusUnauthorized)
	})
	for _, r := range routes {
		assert.Equal(t, http.StatusUnauthorized, probe(t, guarded, r.method, r.path),
			"%s %s did not resolve to a registered route", r.method, r.path)
	}
}

// TestReservedSlugsOmitsAnUnconfiguredPlatformSlug pins what the handler passes to
// the provisioner.
//
// An empty configured slug must produce no reservation rather than a reservation of
// the empty string, which would be compared against every derived slug.
func TestReservedSlugsOmitsAnUnconfiguredPlatformSlug(t *testing.T) {
	assert.Nil(t, NewHandler(nil, nil, nil, "").reservedSlugs())
	assert.Nil(t, NewHandler(nil, nil, nil, "   ").reservedSlugs())

	// Configuration is normalized on the way in, so a deployment that writes the
	// slug with different casing or stray whitespace still reserves it.
	assert.Equal(t, []string{"authn-console"},
		NewHandler(nil, nil, nil, "  Authn-Console  ").reservedSlugs())
}
