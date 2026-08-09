/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/seed_rbac.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: System RBAC roles seeder logic.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
)

// seedRoles creates the system roles and returns them keyed by slug.
//
// Returns an error when a role cannot be created, because the user and
// organization steps assign these roles by the IDs recorded here.
func seedRoles(ctx context.Context, client *ent.Client) (map[string]*ent.Role, error) {
	definitions := []struct {
		ID   string
		Name string
		Slug string
	}{
		{"role_tenant_admin", "Tenant Administrator", "tenant_admin"},
		{"role_org_admin", "Organization Administrator", "org_admin"},
		{"role_editor", "Editor", "editor"},
		{"role_viewer", "Viewer", "viewer"},
	}

	roles := make(map[string]*ent.Role, len(definitions))
	for _, def := range definitions {
		existing, err := client.Role.Query().
			Where(role.TenantID(seedTenantID), role.Slug(def.Slug)).
			Only(ctx)
		if err == nil {
			roles[def.Slug] = existing
			continue
		}

		created, err := client.Role.Create().
			SetID(def.ID).
			SetTenantID(seedTenantID).
			SetName(def.Name).
			SetSlug(def.Slug).
			SetDescription("System role for " + def.Name).
			SetIsSystemRole(true).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("seeding role %s: %w", def.Slug, err)
		}
		roles[def.Slug] = created
	}
	return roles, nil
}
