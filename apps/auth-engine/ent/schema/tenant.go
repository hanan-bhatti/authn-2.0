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
		field.JSON("branding_config", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing brand colors, logo URL, custom CSS, and email templates"),
		field.JSON("password_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing password complexity policy rules"),
		field.JSON("security_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing tenant security policy settings (require_email_verification, email_verification_mode)"),
		field.JSON("recovery_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing tenant account recovery policy rules"),
		field.JSON("social_providers", map[string]interface{}{}).
			Optional().
			Comment("Per-provider OAuth2 configuration keyed by provider name (google, github, discord, etc.). Each entry holds: enabled bool, client_id string, client_secret_encrypted string (AES-256-GCM). Client secrets are never returned in API responses."),
		field.JSON("role_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing tenant role & permission restrictions and assignment policies"),
		field.JSON("session_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing cookie SameSite mode and session/access token lifetimes. Lives here rather than in the environment because a customer changes it and it must take effect without a redeploy; the cookie Domain stays an env value because a server can only set cookies for a domain it is served from."),
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
