/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/session.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the Session entity. Manages active
 *              user login sessions, SHA-256 refresh token hashes, and rotation grace periods.
 *
 * Security Notice:
 *   - Refresh tokens are stored strictly as SHA-256 hashes.
 *   - Superseded tokens are valid only during the 10-second grace window (`rotated_grace`).
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

// Session holds the schema definition for the Session entity.
type Session struct {
	ent.Schema
}

// Fields of the Session.
func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Session ID identifier (e.g. ses_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.String("refresh_token_hash").
			Unique().
			NotEmpty().
			Comment("SHA-256 hash of the 64-byte opaque refresh token"),
		field.Enum("status").
			Values("active", "rotated_grace", "revoked").
			Default("active").
			Comment("Session status: active, rotated_grace (10s rotation grace window), or revoked"),
		field.String("superseded_by_session_id").
			Optional().
			Nillable().
			Comment("ID of the new session that superseded this session upon token rotation"),
		field.String("device_fingerprint_hmac").
			Optional().
			Comment("HMAC-SHA256 digest of client device fingerprint"),
		field.String("ip_address").
			Optional().
			Comment("Client IP address"),
		field.String("user_agent").
			Optional().
			Comment("Client HTTP User-Agent header string"),
		field.String("location").
			Optional().
			Comment("Derived location string (e.g. London, UK)"),
		field.Float("latitude").
			Optional().
			Nillable().
			Comment("Device GPS / HTML5 Geolocation latitude coordinate"),
		field.Float("longitude").
			Optional().
			Nillable().
			Comment("Device GPS / HTML5 Geolocation longitude coordinate"),
		field.Time("last_active_at").
			Optional().
			Nillable().
			Comment("Timestamp when session was last active or refreshed"),
		field.Time("expires_at").
			Comment("Session absolute expiration timestamp"),
		field.Time("grace_expires_at").
			Optional().
			Nillable().
			Comment("Expiration timestamp for the 10-second token rotation grace window"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Session creation timestamp"),
	}
}

// Edges of the Session.
func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("sessions").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the Session.
func (Session) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("refresh_token_hash").Unique(),
		index.Fields("user_id", "status"),
	}
}
