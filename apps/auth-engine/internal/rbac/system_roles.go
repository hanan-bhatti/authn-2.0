/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/system_roles.go
 * Tier: Internal Feature Package / RBAC System Role Provisioning
 *
 * The set of roles every tenant is created with.
 *
 * These lived in the development seeder, hardcoded to the demo tenant, which
 * meant a tenant created any other way had no roles at all: the first admin's
 * claim referenced a role slug with no row behind it, and permission checks
 * silently matched nothing. Provisioning a tenant and installing its roles are
 * therefore the same operation, and this is the one definition both the seeder
 * and any future provisioning path use.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
)

// SystemRoleDefinition describes one role installed into every tenant.
type SystemRoleDefinition struct {
	// Name is the operator-facing label.
	Name string
	// Slug is the stable identifier permission checks and JWT claims carry.
	Slug string
}

// SystemRoles are the roles every tenant receives at provisioning time.
//
// tenant_admin is the one ClaimFirstAdminRole grants to a tenant's first user,
// so its absence would leave a tenant with no administrator.
var SystemRoles = []SystemRoleDefinition{
	{"Tenant Administrator", ConsoleRoleSlug},
	{"Organization Administrator", "org_admin"},
	{"Editor", "editor"},
	{"Viewer", "viewer"},
}

// SystemRoleID returns the deterministic row ID for a system role in a tenant.
//
// The tenant is part of the ID because role rows are per-tenant: a single
// "role_tenant_admin" shared across tenants would collide on the second tenant
// provisioned, and the insert would fail.
func SystemRoleID(tenantID string, slug string) string {
	return fmt.Sprintf("role_%s_%s", tenantID, slug)
}

// EnsureSystemRoles installs the system roles for tenantID and returns them
// keyed by slug.
//
// It is idempotent: an existing role is reused rather than replaced, so running
// it against an already-provisioned tenant neither duplicates rows nor discards
// permission grants an operator has since attached.
//
// The caller supplies the client and a context already scoped to tenantID — or
// a bypass context, when provisioning a tenant that no credential can yet reach.
//
// Returns an error if a role can neither be found nor created, since callers
// assign these roles by the IDs recorded here.
func EnsureSystemRoles(ctx context.Context, client *ent.Client, tenantID string) (map[string]*ent.Role, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("cannot install system roles without a tenant")
	}

	roles := make(map[string]*ent.Role, len(SystemRoles))
	for _, def := range SystemRoles {
		existing, err := client.Role.Query().
			Where(role.TenantID(tenantID), role.Slug(def.Slug)).
			Only(ctx)
		if err == nil {
			roles[def.Slug] = existing
			continue
		}

		created, err := client.Role.Create().
			SetID(SystemRoleID(tenantID, def.Slug)).
			SetTenantID(tenantID).
			SetName(def.Name).
			SetSlug(def.Slug).
			SetDescription("System role for " + def.Name).
			SetIsSystemRole(true).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("installing system role %s for tenant %s: %w", def.Slug, tenantID, err)
		}
		roles[def.Slug] = created
	}
	return roles, nil
}
