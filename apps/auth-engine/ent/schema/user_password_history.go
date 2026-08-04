/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/user_password_history.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for UserPasswordHistory entity. Retains previous password
 *              hashes (up to 2 most recent) for the "Old Password" recovery proof method.
 *
 * Security Notice:
 *   - Passwords must be hashed using Argon2id. Plaintext passwords MUST NEVER be stored.
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

// UserPasswordHistory holds the schema definition for the UserPasswordHistory entity.
type UserPasswordHistory struct {
	ent.Schema
}

// Fields of the UserPasswordHistory.
func (UserPasswordHistory) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Password History ID (e.g. pwh_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.String("password_hash").
			NotEmpty().
			Sensitive().
			Comment("Argon2id password hash of previous password"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when password was replaced/archived"),
	}
}

// Edges of the UserPasswordHistory.
func (UserPasswordHistory) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("password_history").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the UserPasswordHistory.
func (UserPasswordHistory) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "created_at"),
	}
}
