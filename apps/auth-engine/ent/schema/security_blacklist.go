/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/security_blacklist.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Stores 7-day IP, subnet, and device fingerprint blacklist records
 *              generated following security incident cancellations (FR-5).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// SecurityBlacklist holds the schema definition for security blacklist entries.
type SecurityBlacklist struct {
	ent.Schema
}

// Fields of the SecurityBlacklist.
func (SecurityBlacklist) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique blacklist entry ID (e.g. blk_8a9b0c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.String("user_id").
			NotEmpty().
			Comment("Target User ID associated with cancelled recovery attempt"),
		field.String("ip_address").
			Optional().
			Comment("Originating IP address of blacklisted attempt"),
		field.String("subnet").
			Optional().
			Comment("Originating /24 or /48 IP subnet of blacklisted attempt"),
		field.String("fingerprint_hash").
			Optional().
			Comment("SHA-256 hash of User-Agent and Accept-Language client fingerprint"),
		field.String("reason").
			Default("recovery_cancelled").
			Comment("Reason for blacklisting (e.g. recovery_cancelled, security_review)"),
		field.Time("expires_at").
			Comment("Expiration timestamp of blacklist window (7 days from creation)"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Blacklist creation timestamp"),
	}
}

// Edges of the SecurityBlacklist.
func (SecurityBlacklist) Edges() []ent.Edge {
	return nil
}

// Indexes of the SecurityBlacklist.
func (SecurityBlacklist) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "user_id", "expires_at"),
		index.Fields("subnet", "expires_at"),
		index.Fields("fingerprint_hash", "expires_at"),
	}
}
