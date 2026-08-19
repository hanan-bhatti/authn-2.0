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
		field.Enum("environment").
			Values("test", "live").
			Default("test").
			Comment("Workspace environment mode"),
		field.String("name").
			NotEmpty().
			Comment("Organization workspace name"),
		field.String("slug").
			NotEmpty().
			Comment("URL-friendly organization slug"),
		field.String("logo_url").
			Optional().
			Comment("Workspace logo/avatar image URL"),
		field.JSON("metadata", map[string]interface{}{}).
			Optional().
			Comment("Custom metadata attributes (billing_email, stripe_customer_id, plan_tier)"),
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
		edge.To("saml_connections", SAMLConnection.Type),
	}
}

// Indexes of the Organization.
func (Organization) Indexes() []ent.Index {
	return []ent.Index{
		// A slug identifies a workspace within one tenant's environment, not
		// globally. Scoping the uniqueness this way is what lets a team rehearse
		// under the slug they will use in production, and stops one tenant's choice
		// of slug from being unavailable to every other tenant.
		index.Fields("tenant_id", "environment", "slug").Unique(),
		// Serves the tenant listing and the test-environment ceiling's count, both
		// of which read every organization in one environment.
		index.Fields("tenant_id", "environment"),
	}
}
