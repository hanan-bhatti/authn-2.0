/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/application.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the Application entity. Represents
 *              client apps (Web, Mobile, SPA, M2M) registered under a tenant.
 *
 * Security Notice:
 *   - CORS origins and exact redirect URIs are strictly validated.
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

// Application holds the schema definition for the Application entity.
type Application struct {
	ent.Schema
}

// Fields of the Application.
func (Application) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Application ID identifier (e.g. app_9a8b7c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.String("name").
			NotEmpty().
			Comment("Human-readable application name"),
		field.Enum("environment").
			Values("test", "live").
			Default("test").
			Comment("Environment mode: test (development) or live (production)"),
		field.Strings("allowed_cors_origins").
			Optional().
			Comment("Whitelisted HTTP CORS origins for publishable key browser requests"),
		field.Strings("exact_redirect_uris").
			Optional().
			Comment("Strict exact-match redirect URIs permitted for OAuth2/OIDC PKCE login flows"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when application was registered"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Timestamp when application was last modified"),
	}
}

// Edges of the Application.
func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("applications").
			Field("tenant_id").
			Unique().
			Required(),
		edge.To("api_keys", ApiKey.Type),
	}
}

// Indexes of the Application.
func (Application) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "environment"),
	}
}
