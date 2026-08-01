/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/api_key.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the ApiKey entity. Represents
 *              Publishable (`pk_...`) and Secret (`sk_...`) API keys.
 *
 * Security Notice:
 *   - Secret API keys are NEVER stored in plain text.
 *   - `key_hash` stores the peppered HMAC-SHA256 hash of secret admin keys.
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

// ApiKey holds the schema definition for the ApiKey entity.
type ApiKey struct {
	ent.Schema
}

// Fields of the ApiKey.
func (ApiKey) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique API Key ID identifier (e.g. key_1a2b3c)"),
		field.String("application_id").
			NotEmpty().
			Comment("Owning Application ID"),
		field.Enum("type").
			Values("publishable", "secret").
			Comment("Key type: publishable (client SDKs) or secret (admin APIs)"),
		field.String("key_prefix").
			NotEmpty().
			Comment("Key prefix for display (pk_test_, pk_live_, sk_test_, sk_live_)"),
		field.String("key_hash").
			Unique().
			NotEmpty().
			Comment("Peppered HMAC-SHA256 hash of secret key (or raw publishable key string)"),
		field.Enum("environment").
			Values("test", "live").
			Default("test").
			Comment("Key environment scope"),
		field.String("name").
			Optional().
			Comment("Friendly label for key (e.g. Production Web SDK Key)"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Optional key expiration timestamp"),
		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Timestamp when key was last presented in an API request"),
		field.Time("revoked_at").
			Optional().
			Nillable().
			Comment("Timestamp when key was soft-revoked"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Key creation timestamp"),
	}
}

// Edges of the ApiKey.
func (ApiKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("application", Application.Type).
			Ref("api_keys").
			Field("application_id").
			Unique().
			Required(),
	}
}

// Indexes of the ApiKey.
func (ApiKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key_hash").Unique(),
		index.Fields("application_id", "environment"),
	}
}
