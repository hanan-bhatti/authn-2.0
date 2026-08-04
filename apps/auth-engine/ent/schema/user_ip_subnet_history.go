/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/user_ip_subnet_history.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for UserIpSubnetHistory entity. Tracks /24 (IPv4)
 *              and /48 (IPv6) historic subnet interactions per account with 90-day retention.
 *
 * Security Notice:
 *   - Aggregates subnets only (not individual raw IP tracking) for GDPR compliance & ISP movement tolerance.
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

// UserIpSubnetHistory holds the schema definition for the UserIpSubnetHistory entity.
type UserIpSubnetHistory struct {
	ent.Schema
}

// Fields of the UserIpSubnetHistory.
func (UserIpSubnetHistory) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Subnet History ID (e.g. sub_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.String("subnet").
			NotEmpty().
			Comment("Subnet CIDR string (e.g. 198.51.100.0/24 or 2001:db8:abcd::/48)"),
		field.Int("ip_version").
			Comment("IP protocol version: 4 or 6"),
		field.Int("login_count").
			Default(1).
			Comment("Total successful logins/authentications observed from this subnet"),
		field.Time("first_seen_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when subnet was first observed"),
		field.Time("last_seen_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Timestamp when subnet was last observed"),
	}
}

// Edges of the UserIpSubnetHistory.
func (UserIpSubnetHistory) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("ip_subnet_history").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the UserIpSubnetHistory.
func (UserIpSubnetHistory) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "subnet").Unique(),
		index.Fields("last_seen_at"),
	}
}
