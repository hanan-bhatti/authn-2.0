/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/identity.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the Identity entity. Links social
 *              OAuth/OIDC provider identities (Google, Apple, GitHub, X) to users.
 *
 * Security Notice:
 *   - Third-party OAuth tokens are encrypted using KMS AES-256-GCM prior to DB insertion.
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

// Identity holds the schema definition for the Identity entity.
type Identity struct {
	ent.Schema
}

// Fields of the Identity.
func (Identity) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Identity ID identifier (e.g. idn_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.String("provider").
			NotEmpty().
			Comment("Identity provider name (google, apple, github, twitter, facebook, discord)"),
		field.String("provider_user_id").
			NotEmpty().
			Comment("Unique subject/user ID issued by the external provider"),
		field.String("access_token_encrypted").
			Optional().
			Sensitive().
			Comment("AES-256-GCM encrypted provider access token"),
		field.String("refresh_token_encrypted").
			Optional().
			Sensitive().
			Comment("AES-256-GCM encrypted provider refresh token"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Identity creation timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Identity updated timestamp"),
	}
}

// Edges of the Identity.
func (Identity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("identities").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the Identity.
func (Identity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "provider_user_id").Unique(),
		index.Fields("user_id"),
	}
}
