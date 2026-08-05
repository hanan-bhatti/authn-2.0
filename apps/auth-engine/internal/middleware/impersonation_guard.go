/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/impersonation_guard.go
 * Tier: HTTP Delivery Layer / Security Middleware
 *
 * Description: Prevents destructive account mutations (password reset, 2FA removal,
 *              account deletion) during active admin impersonation sessions (FR-14).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// PreventImpersonatedMutations blocks destructive mutations when claims.IsImpersonated == true.
func PreventImpersonatedMutations(signingSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Next()
		}

		tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil || claims == nil {
			return c.Next()
		}

		if claims.IsImpersonated {
			path := strings.ToLower(c.Path())
			method := strings.ToUpper(c.Method())

			isDestructiveMutation := (method == "DELETE" && strings.Contains(path, "/account")) ||
				(method == "PUT" && strings.Contains(path, "/password")) ||
				(method == "POST" && strings.Contains(path, "/password")) ||
				(method == "DELETE" && strings.Contains(path, "/2fa")) ||
				(method == "POST" && strings.Contains(path, "/2fa/disable"))

			if isDestructiveMutation {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "destructive account mutation is disabled during an active impersonation session: read-only security mode active",
					"code":  "impersonation_read_only_restricted",
				})
			}
		}

		return c.Next()
	}
}
