/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/tenant.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the Tenant entity. Represents
 *              top-level customer organizations / isolates in multi-tenant environments.
 *
 * Security Notice:
 *   - Tenant boundary isolation is enforced via Ent privacy hooks.
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

// Tenant holds the schema definition for the Tenant entity.
type Tenant struct {
	ent.Schema
}

// Fields of the Tenant.
func (Tenant) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Tenant ID identifier (e.g. tnt_1a2b3c)"),
		field.String("name").
			NotEmpty().
			Comment("Human-readable organization or company name"),
		field.String("slug").
			Unique().
			NotEmpty().
			Comment("URL-friendly slug identifier"),
		field.String("custom_domain").
			Optional().
			Nillable().
			Unique().
			Comment("Optional verified custom login domain (e.g. auth.acme.com)"),
		field.Bool("domain_verified").
			Default(false).
			Comment("Flag indicating if the custom domain DNS ownership has been verified"),
		field.String("domain_verification_token").
			Optional().
			Comment("TXT record token used for DNS ownership verification"),
		field.Bool("first_admin_claimed").
			Default(false).
			Comment("Atomic flag: true once the first tenant_admin role has been claimed via signup. Set via a conditional UPDATE (WHERE first_admin_claimed = false) to prevent concurrent signups from both receiving tenant_admin (TOCTOU race fix)."),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when the tenant was created"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Timestamp when the tenant was last updated"),
	}
}

// Edges of the Tenant.
func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("applications", Application.Type),
		edge.To("users", User.Type),
		edge.To("organizations", Organization.Type),
		edge.To("roles", Role.Type),
		edge.To("webhook_endpoints", WebhookEndpoint.Type),
		edge.To("audit_logs", AuditLog.Type),
		// environments hold the settings a customer can change, one row per
		// environment. They are an edge rather than columns on this row because test
		// and live must be configurable independently — see
		// ent/schema/tenant_environment.go.
		edge.To("environments", TenantEnvironment.Type),
		edge.To("sandbox_messages", SandboxMessage.Type),
		// managed_tenants are the control plane's ownership records, and exist only
		// on the platform tenant: each row says "this platform user owns that
		// customer tenant". The edge is declared so the join is generated, but the
		// ManagedTenant side deliberately keeps managed_tenant_id and owner_user_id
		// as plain strings — see ent/schema/managed_tenant.go.
		edge.To("managed_tenants", ManagedTenant.Type),
	}
}

// Indexes of the Tenant.
func (Tenant) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("slug").Unique(),
		index.Fields("custom_domain").Unique(),
	}
}
