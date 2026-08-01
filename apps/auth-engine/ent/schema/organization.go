/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/organization.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the Organization entity. Represents
 *              B2B workspace teams within a tenant.
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

// Organization holds the schema definition for the Organization entity.
type Organization struct {
	ent.Schema
}

// Fields of the Organization.
func (Organization) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Organization ID identifier (e.g. org_1a2b3c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.String("name").
			NotEmpty().
			Comment("Organization workspace name"),
		field.String("slug").
			Unique().
			NotEmpty().
			Comment("URL-friendly organization slug"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
	}
}

// Edges of the Organization.
func (Organization) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("organizations").
			Field("tenant_id").
			Unique().
			Required(),
		edge.To("members", OrgMember.Type),
		edge.To("invitations", OrgInvitation.Type),
	}
}

// Indexes of the Organization.
func (Organization) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "slug").Unique(),
	}
}
