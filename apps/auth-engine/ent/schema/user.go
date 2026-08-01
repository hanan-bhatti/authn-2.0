/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/user.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the User entity. Stores core
 *              user account credentials, Argon2id password hash, and profile data.
 *
 * Security Notice:
 *   - Passwords must be hashed using RFC 9106 Argon2id (t=3, m=64MB, p=4).
 *   - Plain text passwords MUST NEVER be stored.
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

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique User ID identifier (e.g. usr_9a8b7c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.Enum("environment").
			Values("test", "live").
			Default("test").
			Comment("Account environment mode"),
		field.String("email").
			NotEmpty().
			Comment("User registered email address"),
		field.String("password_hash").
			Optional().
			Sensitive().
			Comment("Argon2id password hash (t=3, m=64MB, p=4). Omitted for pure social users"),
		field.Bool("email_verified").
			Default(false).
			Comment("Flag indicating if email address has been verified"),
		field.String("phone_number").
			Optional().
			Comment("User registered phone number (E.164 format)"),
		field.Bool("phone_verified").
			Default(false).
			Comment("Flag indicating if phone number has been verified"),
		field.String("name").
			Optional().
			Comment("User full name"),
		field.String("avatar_url").
			Optional().
			Comment("User profile avatar image URL"),
		field.String("locale").
			Optional().
			Comment("Preferred locale string (e.g. en-US, es-ES, ur-PK)"),
		field.Enum("status").
			Values("active", "banned", "recovery_hold").
			Default("active").
			Comment("Account status: active, banned, or recovery_hold (48h security freeze)"),
		field.Time("last_sign_in_at").
			Optional().
			Nillable().
			Comment("Timestamp when user last successfully logged in"),
		field.JSON("metadata", map[string]interface{}{}).
			Optional().
			Comment("Custom key-value metadata attributes for user profile"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("User registration timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("User profile last updated timestamp"),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("users").
			Field("tenant_id").
			Unique().
			Required(),
		edge.To("identities", Identity.Type),
		edge.To("sessions", Session.Type),
		edge.To("two_factor_methods", TwoFactorMethod.Type),
		edge.To("push_devices", PushDevice.Type),
		edge.To("org_memberships", OrgMember.Type),
		edge.To("user_roles", UserRole.Type),
	}
}

// Indexes of the User.
func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "environment", "email").Unique(),
	}
}
