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

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
)

// seedRoles installs the system roles for the seeded tenant and returns them
// keyed by slug.
//
// The definitions live in internal/rbac so that every tenant gets the same set,
// however it was created; this only names the tenant to install them into.
//
// Returns an error when a role cannot be created, because the user and
// organization steps assign these roles by the IDs recorded here.
func seedRoles(ctx context.Context, client *ent.Client) (map[string]*ent.Role, error) {
	return rbac.EnsureSystemRoles(ctx, client, seedTenantID)
}
