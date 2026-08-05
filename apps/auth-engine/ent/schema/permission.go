/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/permission.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the Permission entity. Stores fine-grained
 *              permission strings (e.g. posts:create, users:delete) granted to Roles.
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

// Permission holds the schema definition for the Permission entity.
type Permission struct {
	ent.Schema
}

// Fields of the Permission.
func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Permission ID identifier (e.g. prm_1a2b3c)"),
		field.String("role_id").
			NotEmpty().
			Comment("Owning Role ID"),
		field.String("action").
			NotEmpty().
			Comment("Permission action string (e.g. posts:create, users:delete)"),
		field.String("description").
			Optional().
			Comment("Optional description explaining what the permission enables"),
		field.String("created_by_user_id").
			Optional().
			Nillable().
			Comment("User ID of admin who created this permission"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
	}
}

// Edges of the Permission.
func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("role", Role.Type).
			Ref("permissions").
			Field("role_id").
			Unique().
			Required(),
	}
}

// Indexes of the Permission.
func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "action").Unique(),
	}
}
