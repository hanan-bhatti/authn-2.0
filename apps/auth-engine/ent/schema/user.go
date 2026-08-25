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
		field.String("username").
			Optional().
			Nillable().
			Comment("Optional unique username in the form the user typed it (e.g. AlexSmith). Display only — every lookup and the uniqueness guarantee use username_canonical"),
		field.String("username_canonical").
			Optional().
			Nillable().
			Comment("NFKC-normalised, lower-cased form of username. Carries the unique index and answers every username lookup, so a stored value is compared directly instead of through LOWER(), which no index can serve"),
		field.String("password_hash").
			Optional().
			Sensitive().
			Comment("Argon2id password hash (t=3, m=64MB, p=4). Omitted for pure social users"),
		field.Bool("email_verified").
			Default(false).
			Comment("Flag indicating if email address has been verified"),
		field.String("email_verification_token").
			Optional().
			Nillable().
			Sensitive().
			Comment("SHA-256 hash of active single-use email verification token"),
		field.Time("email_verification_expires_at").
			Optional().
			Nillable().
			Comment("Expiration timestamp of active email verification token"),
		field.String("magic_link_token").
			Optional().
			Nillable().
			Sensitive().
			Comment("SHA-256 hash of active single-use passwordless magic link token"),
		field.Time("magic_link_expires_at").
			Optional().
			Nillable().
			Comment("Expiration timestamp of active magic link token"),
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
			// Appended rather than grouped next to "banned" on purpose: MySQL
			// stores an enum by ordinal, so inserting a value mid-list renumbers
			// every value after it and rewrites the column. Appending leaves
			// existing rows untouched.
			Values("active", "banned", "recovery_hold", "suspended").
			Default("active").
			Comment("Account status: active, banned (permanent), recovery_hold (48h security freeze), or suspended (reversible)"),
		field.Time("deleted_at").
			Optional().
			Nillable().
			Comment("Soft-deletion timestamp. The row is retained so the email stays reserved — a second signup on that address is refused while it exists"),
		field.Time("last_sign_in_at").
			Optional().
			Nillable().
			Comment("Timestamp when user last successfully logged in"),
		field.JSON("metadata", map[string]interface{}{}).
			Optional().
			Comment("Custom key-value metadata attributes for user profile"),
		field.Int("recovery_failed_attempts").
			Default(0).
			Comment("Consecutive failed recovery proof attempts count for exponential lockout schedule"),
		field.Time("recovery_lockout_until").
			Optional().
			Nillable().
			Comment("Expiration timestamp of current exponential lockout penalty window"),
		field.Bool("security_review_required").
			Default(false).
			Comment("Flag requiring password reset & 2FA review following a cancelled recovery attempt"),
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
		edge.To("trusted_devices", TrustedDevice.Type),
		edge.To("ip_subnet_history", UserIpSubnetHistory.Type),
		edge.To("recovery_contacts", RecoveryContact.Type),
		edge.To("password_history", UserPasswordHistory.Type),
		edge.To("recovery_requests", RecoveryRequest.Type),
	}
}

// Indexes of the User.
func (User) Indexes() []ent.Index {
	return []ent.Index{
		// Unique on email with no regard for deleted_at, which is what reserves a
		// soft-deleted user's address: the row still occupies the slot, so a
		// second signup on it is refused by the database rather than by a check
		// someone has to remember to write.
		index.Fields("tenant_id", "environment", "email").Unique(),
		// Unique on the canonical form, which is what makes two concurrent claims on
		// one handle resolve to a constraint violation rather than two rows. The
		// column is NULL for a user who has set no username, and SQL treats NULLs as
		// distinct, so any number of users may hold none.
		index.Fields("tenant_id", "environment", "username_canonical").Unique(),
		// Serves the admin listing, which pages users filtered by status and
		// hides soft-deleted rows by default.
		index.Fields("tenant_id", "environment", "status", "deleted_at"),
	}
}
