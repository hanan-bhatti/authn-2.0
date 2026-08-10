/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/testctx_test.go
 * Tier: Internal Feature Package / Test Support
 *
 * The context these tests drive services with.
 *
 * The privacy interceptors narrow every query to the tenant on the context and
 * refuse a query that has none, which in a running server is established by the
 * authenticating middleware. These are service-level tests with no middleware
 * in front of them, so they supply the scope themselves.
 *
 * testCtx bypasses the boundary rather than naming a tenant, because these
 * fixtures build rows across tenants and environments before any credential for
 * them exists — the same reason the seeder and the integration harness do. It
 * is not a statement that the boundary does not apply: tenant isolation is
 * asserted directly in internal/privacy, internal/org/isolation_test.go and
 * internal/apikey/isolation_test.go, which construct real scoped contexts and
 * assert that one tenant cannot read another's rows.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"context"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// testCtx returns a context that satisfies the privacy interceptors.
func testCtx() context.Context {
	return privacy.NewBypassContext(context.Background())
}

// testScopeMiddleware stands in for the publishable-key middleware on tests that
// exercise the HTTP surface directly.
//
// In a running server RequirePublishableKey resolves the caller's key to a
// tenant and installs the privacy scope every downstream query needs. These
// tests mount their routes without it, so requests would otherwise arrive with
// no scope and be refused. It sets the same locals and scope the real
// middleware does, for the given tenant, and authenticates nothing — it is a
// scope stub, not a credential check.
func testScopeMiddleware(tenantID string, environment string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.SetUserContext(privacy.NewContext(c.UserContext(), tenantID, "", environment))
		c.Locals("tenant_id", tenantID)
		c.Locals("environment", environment)
		return c.Next()
	}
}
