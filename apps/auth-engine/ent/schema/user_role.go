/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/user_role.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the UserRole entity. Join table
 *              linking Users to global Tenant Roles.
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

// UserRole holds the schema definition for the UserRole entity.
type UserRole struct {
	ent.Schema
}

// Fields of the UserRole.
func (UserRole) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique UserRole ID identifier (e.g. url_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Associated User ID"),
		field.String("role_id").
			NotEmpty().
			Comment("Assigned Role ID"),
		field.String("assigned_by_user_id").
			Optional().
			Nillable().
			Comment("User ID of admin who assigned this role initially"),
		field.String("updated_by_user_id").
			Optional().
			Nillable().
			Comment("User ID of admin who last modified this role assignment"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Last updated timestamp"),
	}
}

// Edges of the UserRole.
func (UserRole) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("user_roles").
			Field("user_id").
			Unique().
			Required(),
		edge.From("role", Role.Type).
			Ref("user_roles").
			Field("role_id").
			Unique().
			Required(),
	}
}

// Indexes of the UserRole.
func (UserRole) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "role_id").Unique(),
	}
}
