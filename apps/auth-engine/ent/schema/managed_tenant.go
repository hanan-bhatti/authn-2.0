/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/managed_tenant.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the ManagedTenant entity. Records
 *              which platform user owns which customer tenant, for the hosted
 *              control plane.
 *
 * Security Notice:
 *   - tenant_id on this entity is the PLATFORM tenant, not the tenant being
 *     described. The row is control-plane data, so the privacy interceptor scopes
 *     it to the control plane like any other tenant-owned row. An owner_user_id
 *     field on Tenant itself could not work: the interceptor unconditionally
 *     narrows a Tenant query to the caller's own tenant, so a query for "the
 *     tenants this user owns" would filter down to the platform tenant and return
 *     nothing.
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

// ManagedTenant holds the schema definition for the ManagedTenant entity.
type ManagedTenant struct {
	ent.Schema
}

// Fields of the ManagedTenant.
func (ManagedTenant) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique ManagedTenant ID identifier (e.g. mtn_1a2b3c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("The PLATFORM tenant that owns this ownership record — not the tenant being managed. This is what the privacy interceptor filters on."),
		field.String("managed_tenant_id").
			NotEmpty().
			Immutable().
			Comment("The customer tenant being managed. A plain indexed string with no edge: an edge would generate an eager-load whose query the interceptor scopes to the platform tenant, silently yielding a nil edge instead of the customer tenant. Resolve it through a confined bypass after authorization instead."),
		field.String("owner_user_id").
			NotEmpty().
			Immutable().
			Comment("The platform-tenant user who owns or belongs to the managed tenant. A plain indexed string with no edge, for the same reason as managed_tenant_id."),
		field.Enum("role").
			Values("owner", "member").
			Default("owner").
			Comment("Whether this user owns the managed tenant or merely has access to it"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when the ownership record was created"),
	}
}

// Edges of the ManagedTenant.
func (ManagedTenant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("managed_tenants").
			Field("tenant_id").
			Unique().
			Required(),
	}
}

// Indexes of the ManagedTenant.
func (ManagedTenant) Indexes() []ent.Index {
	return []ent.Index{
		// Listing what a platform user owns is the read this entity exists for.
		index.Fields("tenant_id", "owner_user_id"),
		// One ownership row per (user, managed tenant): re-provisioning must not
		// accumulate duplicates, and the uniqueness makes an upsert well-defined.
		index.Fields("owner_user_id", "managed_tenant_id").Unique(),
		// Reverse lookup: who owns this customer tenant.
		index.Fields("managed_tenant_id"),
	}
}
