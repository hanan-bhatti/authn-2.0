/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/org_member.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the OrgMember entity. Join table
 *              linking Users to Organizations with assigned Roles.
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

// OrgMember holds the schema definition for the OrgMember entity.
type OrgMember struct {
	ent.Schema
}

// Fields of the OrgMember.
func (OrgMember) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique OrgMember ID identifier (e.g. mem_1a2b3c)"),
		field.String("organization_id").
			NotEmpty().
			Comment("Owning Organization ID"),
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
			Comment("Membership creation timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Membership last updated timestamp"),
	}
}

// Edges of the OrgMember.
func (OrgMember) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("members").
			Field("organization_id").
			Unique().
			Required(),
		edge.From("user", User.Type).
			Ref("org_memberships").
			Field("user_id").
			Unique().
			Required(),
		edge.From("role", Role.Type).
			Ref("org_members").
			Field("role_id").
			Unique().
			Required(),
	}
}

// Indexes of the OrgMember.
func (OrgMember) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id", "user_id").Unique(),
	}
}
