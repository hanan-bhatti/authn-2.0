/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/guard_once.go
 * Tier: HTTP Middleware Layer / Guard Coordination
 *
 * Keeps an authentication guard from verifying the same credential more than
 * once on a single request.
 *
 * Route groups are mounted per feature package, and several packages mount a
 * group at the same prefix: /v1/admin, /v1/tenant and /v1/client each carry
 * three or more. Fiber treats a group's middleware as a prefix match rather than
 * a route match, so every registration under a matching prefix contributes one
 * link to the chain — a request to /v1/admin/audit-logs runs the admin guard
 * once for each package that mounted /v1/admin, and again for the audit group
 * itself.
 *
 * The repeats are consistent, since the same credential on the same request
 * resolves the same way each time. They are not free: each pass costs an API key
 * lookup or a token verification, and on the client surface two Redis round
 * trips besides. The first pass is authoritative and the rest are skipped.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import "github.com/gofiber/fiber/v2"

// Sentinels recording which guard has already authenticated the request.
//
// Each guard carries its own. They resolve different credentials against
// different stores, so one having run says nothing about another, and a single
// shared "authenticated" flag would let whichever guard ran first satisfy the
// rest — turning a publishable key into an admin credential.
const (
	guardAdminAuth      = "authn_guard_admin_auth"
	guardClientAuth     = "authn_guard_client_auth"
	guardPublishableKey = "authn_guard_publishable_key"
)

// guardCompleted reports whether the named guard has already admitted this
// request.
//
// Only a successful pass records itself, so a rejected credential is never
// mistaken for a completed one: a guard that refuses writes its response and
// never reaches the next link in the chain.
func guardCompleted(c *fiber.Ctx, guard string) bool {
	done, _ := c.Locals(guard).(bool)
	return done
}

// markGuardCompleted records that a guard has admitted this request, and must be
// called only on the path that also calls c.Next().
func markGuardCompleted(c *fiber.Ctx, guard string) {
	c.Locals(guard, true)
}
