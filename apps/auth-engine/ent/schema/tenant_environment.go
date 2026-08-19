/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/tenant_environment.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the TenantEnvironment entity. Holds one
 *              tenant's runtime-changeable settings for one environment, so the test
 *              and live sides of a tenant can be configured independently.
 *
 * Security Notice:
 *   - Environment isolation is enforced via the Ent privacy interceptor, which
 *     narrows this entity by tenant_id and environment together.
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

// TenantEnvironment holds the schema definition for the TenantEnvironment entity.
//
// A tenant has exactly one row per environment, and every policy a customer can
// change lives here rather than on the tenant. That is what makes a policy change
// rehearsable: raising the password minimum in test governs test sign-ins alone,
// and reaches live only when it is deliberately published.
//
// The environment split is otherwise a read filter over data — it separates which
// users a key can see. Settings are behaviour rather than data, so a filter cannot
// separate them; they have to be stored per environment to differ at all.
type TenantEnvironment struct {
	ent.Schema
}

// Fields of the TenantEnvironment.
func (TenantEnvironment) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Tenant Environment ID identifier (e.g. tenv_1a2b3c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.Enum("environment").
			Values("test", "live").
			Immutable().
			Comment("Which environment these settings govern. Immutable: the pair (tenant_id, environment) identifies the row, and repointing it would move a whole configuration between environments in one write. There is deliberately no default, because a settings row that does not say which environment it configures is not a meaningful row."),
		field.JSON("branding_config", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing brand colors, logo URL, custom CSS, and email templates"),
		field.JSON("password_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing password complexity policy rules"),
		field.JSON("security_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing tenant security policy settings (require_email_verification, email_verification_mode), including the nested impersonation_policy key"),
		field.JSON("recovery_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing tenant account recovery policy rules"),
		field.JSON("social_providers", map[string]interface{}{}).
			Optional().
			Comment("Per-provider OAuth2 configuration keyed by provider name (google, github, discord, etc.). Each entry holds: enabled bool, client_id string, client_secret_encrypted string (AES-256-GCM). Client secrets are never returned in API responses. Held per environment so a sandbox can point at a provider's test credentials while live points at the real ones."),
		field.JSON("role_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing tenant role & permission restrictions and assignment policies"),
		field.JSON("session_policy", map[string]interface{}{}).
			Optional().
			Comment("JSON blob containing cookie SameSite mode and session/access token lifetimes. Lives here rather than in the deployment environment because a customer changes it and it must take effect without a redeploy; the cookie Domain stays an env value because a server can only set cookies for a domain it is served from."),
		field.Time("published_at").
			Optional().
			Nillable().
			Comment("When this row last received a published copy of another environment's settings. Nil on a row that has only ever been edited directly."),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when the settings row was created"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Timestamp when the settings row was last updated"),
	}
}

// Edges of the TenantEnvironment.
func (TenantEnvironment) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("environments").
			Field("tenant_id").
			Unique().
			Required(),
	}
}

// Indexes of the TenantEnvironment.
func (TenantEnvironment) Indexes() []ent.Index {
	return []ent.Index{
		// Unique because a tenant configuring one environment twice would leave the
		// engine with two answers to every policy question and no rule for choosing.
		index.Fields("tenant_id", "environment").Unique(),
	}
}
