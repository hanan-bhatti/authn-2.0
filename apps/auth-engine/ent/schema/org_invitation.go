/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/org_invitation.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the OrgInvitation entity. Represents
 *              pending team member invitations with single-use 7-day tokens.
 *
 * Security Notice:
 *   - `invitation_token` must be cryptographically single-use.
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

// OrgInvitation holds the schema definition for the OrgInvitation entity.
type OrgInvitation struct {
	ent.Schema
}

// Fields of the OrgInvitation.
func (OrgInvitation) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Invitation ID identifier (e.g. inv_1a2b3c)"),
		field.String("organization_id").
			NotEmpty().
			Comment("Owning Organization ID"),
		field.String("email").
			NotEmpty().
			Comment("Invitee email address"),
		field.String("role_id").
			NotEmpty().
			Comment("Assigned Role ID upon invitation acceptance"),
		field.String("invited_by_user_id").
			Optional().
			Nillable().
			Comment("User ID of the admin or team member who sent the invitation"),
		field.String("invitation_token").
			Unique().
			NotEmpty().
			Comment("Single-use cryptographically random 32-byte invitation token"),
		field.Enum("status").
			Values("pending", "accepted", "expired").
			Default("pending").
			Comment("Invitation status: pending, accepted, or expired"),
		field.Time("expires_at").
			Comment("Invitation expiration timestamp (7-day default)"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
	}
}

// Edges of the OrgInvitation.
func (OrgInvitation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("invitations").
			Field("organization_id").
			Unique().
			Required(),
	}
}

// Indexes of the OrgInvitation.
func (OrgInvitation) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("invitation_token").Unique(),
		index.Fields("organization_id", "email"),
	}
}
