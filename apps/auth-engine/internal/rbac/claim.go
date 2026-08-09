/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/claim.go
 * Tier: Security & Authorization Layer
 *
 * Resolution of the JWT `role` claim from the roles actually recorded in the
 * database. Every token-issuing path — login, refresh, 2FA, magic link, OAuth,
 * social, session rotation, signup — calls this, so a console administrator's
 * access follows their role assignment rather than the path they signed in by.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
)

// ConsoleRoleSlug is the only role slug the console auth middlewares accept in a
// JWT `role` claim (middleware.RequireAdminAuth, middleware.RequireConsoleAuth).
const ConsoleRoleSlug = "tenant_admin"

// ResolveConsoleRoleClaim returns the role slug to embed in a user's JWT `role`
// claim, or "" when the user holds no console-admin role.
//
// It fails closed: a nil client, an empty user ID, or any query error yields ""
// rather than a privileged claim, so a database problem can only ever withhold
// console access, never grant it.
func ResolveConsoleRoleClaim(ctx context.Context, client *ent.Client, userID string) string {
	if client == nil || userID == "" {
		return ""
	}
	userRoles, err := client.UserRole.Query().
		Where(userrole.UserID(userID)).
		WithRole().
		All(ctx)
	if err != nil {
		return ""
	}
	for _, ur := range userRoles {
		if ur.Edges.Role != nil && ur.Edges.Role.Slug == ConsoleRoleSlug {
			return ConsoleRoleSlug
		}
	}
	return ""
}
