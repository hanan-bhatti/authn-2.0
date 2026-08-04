/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/trusted_device.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the TrustedDevice entity. Stores cryptographically
 *              signed device token hashes and client fingerprint metrics for recognized devices.
 *
 * Security Notice:
 *   - Raw token cookies MUST NEVER be stored; only SHA-256 hashes are persisted.
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

// TrustedDevice holds the schema definition for the TrustedDevice entity.
type TrustedDevice struct {
	ent.Schema
}

// Fields of the TrustedDevice.
func (TrustedDevice) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique TrustedDevice ID identifier (e.g. trd_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.String("device_token_hash").
			Unique().
			NotEmpty().
			Comment("SHA-256 hash of the authn_td_token cookie"),
		field.String("fingerprint_hash").
			NotEmpty().
			Comment("SHA-256 hash of User-Agent and client HTTP header characteristics"),
		field.String("device_name").
			Optional().
			Comment("Derived device hardware/browser name (e.g. Chrome 128 on macOS)"),
		field.String("last_ip_address").
			NotEmpty().
			Comment("Last IP address associated with this trusted device"),
		field.String("last_ip_subnet").
			NotEmpty().
			Comment("Last /24 (IPv4) or /48 (IPv6) subnet range associated with this device"),
		field.Enum("status").
			Values("active", "revoked", "expired").
			Default("active").
			Comment("Trusted device state"),
		field.Time("first_seen_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when device was first registered"),
		field.Time("last_seen_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Timestamp when device was last authenticated"),
		field.Time("expires_at").
			Comment("Sliding 90-day expiration timestamp"),
	}
}

// Edges of the TrustedDevice.
func (TrustedDevice) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("trusted_devices").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the TrustedDevice.
func (TrustedDevice) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("device_token_hash").Unique(),
		index.Fields("user_id", "status"),
		index.Fields("expires_at"),
	}
}
