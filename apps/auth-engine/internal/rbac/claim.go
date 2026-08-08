/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/claim.go
 * Tier: Security & Authorization Layer
 *
 * Description: Resolves the JWT `role` claim from the roles actually recorded in the
 *              database. Single source of truth shared by every token-issuing path.
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
// The claim was previously populated only by the signup path, where the first
// user of a tenant atomically claims tenant_admin; every other issuance path
// (login, refresh, 2FA, magic link, OAuth, social, session rotation) hardcoded
// "". A tenant admin therefore lost console access the moment the signup token
// expired 15 minutes later and could never regain it by logging back in.
//
// Fails closed: any query error yields "" rather than a privileged claim.
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
