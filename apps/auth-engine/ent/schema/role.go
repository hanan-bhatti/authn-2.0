/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/role.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the Role entity. Defines tenant-wide
 *              or organization RBAC roles (e.g. admin, editor, viewer).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Role holds the schema definition for the Role entity.
type Role struct {
	ent.Schema
}

// Fields of the Role.
func (Role) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Role ID identifier (e.g. rol_1a2b3c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.String("name").
			NotEmpty().
			Comment("Role human-readable name (e.g. Support Agent)"),
		field.String("slug").
			NotEmpty().
			Comment("URL/API-friendly slug identifier (e.g. support_agent). Unique per tenant."),
		field.String("description").
			Optional().
			Comment("Optional role description"),
		field.Bool("is_system_role").
			Default(false).
			Comment("Flag indicating if this is a built-in system role that cannot be deleted"),
		field.String("created_by_user_id").
			Optional().
			Nillable().
			Comment("User ID of admin who created this role"),
		field.String("updated_by_user_id").
			Optional().
			Nillable().
			Comment("User ID of admin who last modified this role"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Last updated timestamp"),
	}
}

// Edges of the Role.
func (Role) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("roles").
			Field("tenant_id").
			Unique().
			Required(),
		edge.To("permissions", Permission.Type),
		edge.To("user_roles", UserRole.Type),
		edge.To("org_members", OrgMember.Type),
	}
}

// Indexes of the Role.
func (Role) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("tenant_id", "slug").Unique(),
	}
}
