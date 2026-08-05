/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/middleware.go
 * Tier: HTTP Middleware Layer / RBAC Authorization Guards
 *
 * Description: Fiber middleware functions for enforcing fine-grained role and permission
 *              checks on protected HTTP endpoints.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// ExtractUserID extracts the authenticated user ID from Fiber locals context.
func ExtractUserID(c *fiber.Ctx) string {
	if val, ok := c.Locals("userID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("user_id").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("console_user_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// RequirePermission returns a Fiber middleware enforcing that the caller possesses requiredPerm.
func RequirePermission(svc *Service, requiredPerm string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := ExtractUserID(c)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unauthorized: user authentication context missing",
			})
		}

		roles, permissions, err := svc.GetUserRBAC(c.UserContext(), userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to evaluate user permissions",
			})
		}

		// Super-admin role bypass
		for _, r := range roles {
			if r == "tenant_admin" || r == "admin" || r == "super_admin" {
				return c.Next()
			}
		}

		// Permission matching (exact match or wildcard)
		for _, perm := range permissions {
			if hasPermission(perm, requiredPerm) {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":               "forbidden: insufficient permissions",
			"required_permission": requiredPerm,
		})
	}
}

// RequireRole returns a Fiber middleware enforcing that the caller possesses requiredRole.
func RequireRole(svc *Service, requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := ExtractUserID(c)
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "unauthorized: user authentication context missing",
			})
		}

		roles, _, err := svc.GetUserRBAC(c.UserContext(), userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to evaluate user roles",
			})
		}

		for _, r := range roles {
			if r == requiredRole || r == "tenant_admin" || r == "super_admin" {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":         "forbidden: required role missing",
			"required_role": requiredRole,
		})
	}
}

// hasPermission checks if granted permission string covers the required permission.
func hasPermission(granted, required string) bool {
	if granted == "*" || granted == required {
		return true
	}
	if strings.HasSuffix(granted, ":*") {
		prefix := strings.TrimSuffix(granted, "*")
		return strings.HasPrefix(required, prefix)
	}
	if strings.HasPrefix(granted, "*:") {
		suffix := strings.TrimPrefix(granted, "*")
		return strings.HasSuffix(required, suffix)
	}
	return false
}
