/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/middleware.go
 * Tier: HTTP Middleware Layer / RBAC Authorization Guards
 *
 * Route guards that enforce a required permission or role before a handler runs.
 *
 * Both guards resolve the caller's roles and permissions from the database on
 * each request rather than trusting a token claim, so a revoked role takes
 * effect immediately instead of at the next token refresh. Both fail closed: an
 * unidentifiable caller or a failed lookup denies.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"github.com/gofiber/fiber/v2"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// ExtractUserID returns the authenticated caller's user ID from the request
// locals, trying the end-user spellings before the console one, or "" when the
// request carries no identity.
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

// RequirePermission returns a Fiber middleware that admits only callers holding
// requiredPerm, whether directly, through a wildcard grant, or by way of a
// privileged administrative role.
//
// It answers 401 when the request carries no identity, 500 when the caller's
// roles cannot be read, and 403 when they are read and do not cover the
// permission. The lookup failure denies rather than admits: an unknown authority
// is not authority.
func RequirePermission(svc *Service, requiredPerm string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := ExtractUserID(c)
		if userID == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"authentication required")
		}

		roles, permissions, err := svc.GetUserRBAC(c.UserContext(), userID)
		if err != nil {
			return httperr.SendInternal(c, "rbac.evaluate_permissions", err)
		}

		if HasPrivilegedRole(roles) {
			return c.Next()
		}

		for _, perm := range permissions {
			if PermissionMatches(perm, requiredPerm) {
				return c.Next()
			}
		}

		// The required permission is named so a caller can tell which grant is
		// missing; it discloses nothing they could not infer from the route.
		return httperr.Forbidden(c, httperr.CodeInsufficientScope,
			"insufficient permissions: "+requiredPerm+" is required")
	}
}

// RequireRole returns a Fiber middleware that admits only callers holding
// requiredRole, or any privileged administrative role.
//
// It answers 401 when the request carries no identity, 500 when the caller's
// roles cannot be read, and 403 when the role is absent.
func RequireRole(svc *Service, requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := ExtractUserID(c)
		if userID == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"authentication required")
		}

		roles, _, err := svc.GetUserRBAC(c.UserContext(), userID)
		if err != nil {
			return httperr.SendInternal(c, "rbac.evaluate_roles", err)
		}

		for _, r := range roles {
			if r == requiredRole || IsPrivilegedRole(r) {
				return c.Next()
			}
		}

		return httperr.Forbidden(c, httperr.CodeInsufficientScope,
			"insufficient permissions: the "+requiredRole+" role is required")
	}
}
