/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/degraded_mode.go
 * Tier: Internal Middleware Layer
 *
 * Description: Middleware that detects Redis cache outages and injects the
 *              X-Authn-Degraded-Mode response header to inform client SDKs to fall back
 *              to direct DB queries without breaking user sessions.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"github.com/gofiber/fiber/v2"
)

// DegradedModeHeader injects X-Authn-Degraded-Mode header when running in fallback mode.
func DegradedModeHeader(isDegraded bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if isDegraded {
			c.Set("X-Authn-Degraded-Mode", "true")
		} else {
			c.Set("X-Authn-Degraded-Mode", "false")
		}
		return c.Next()
	}
}
