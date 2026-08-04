/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/recovery_contact.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for RecoveryContact entity. Stores pre-enrolled trusted
 *              guardians for Shamir's Secret Sharing account recovery.
 *
 * Security Notice:
 *   - Raw Shamir shares MUST NEVER be stored. Only SHA-256 hashes of shares are persisted for verification.
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

// RecoveryContact holds the schema definition for the RecoveryContact entity.
type RecoveryContact struct {
	ent.Schema
}

// Fields of the RecoveryContact.
func (RecoveryContact) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique RecoveryContact ID identifier (e.g. gdn_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.String("guardian_email").
			NotEmpty().
			Comment("Email address of trusted recovery contact"),
		field.String("guardian_name").
			NotEmpty().
			Comment("Name or label of trusted recovery contact"),
		field.Int("share_index").
			Comment("Index of Shamir share (1 to 5) assigned to this guardian"),
		field.String("share_hash").
			NotEmpty().
			Sensitive().
			Comment("SHA-256 hash of guardian's Shamir share for verification"),
		field.Enum("status").
			Values("pending_invite", "active", "revoked").
			Default("pending_invite").
			Comment("Status of guardian enrollment"),
		field.String("invitation_token_hash").
			Optional().
			Nillable().
			Sensitive().
			Comment("SHA-256 hash of active invitation token for enrollment handshake"),
		field.Time("invitation_expires_at").
			Optional().
			Nillable().
			Comment("Expiration timestamp for guardian invitation token"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Enrollment initiation timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Last updated timestamp"),
	}
}

// Edges of the RecoveryContact.
func (RecoveryContact) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("recovery_contacts").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the RecoveryContact.
func (RecoveryContact) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "guardian_email").Unique(),
		index.Fields("user_id", "share_index").Unique(),
	}
}
