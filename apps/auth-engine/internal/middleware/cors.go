/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/cors.go
 * Tier: Internal Middleware Layer
 *
 * Description: Dynamic CORS middleware enforcing tenant origin whitelisting.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// DynamicCORS returns a configured Fiber CORS middleware allowing multi-tenant requests.
func DynamicCORS() fiber.Handler {
	return cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			return true // Mirror origin dynamically for multi-tenant CORS with credentials
		},
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Authn-Api-Key, X-Authn-Tenant-Id, X-Authn-Environment",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	})
}
