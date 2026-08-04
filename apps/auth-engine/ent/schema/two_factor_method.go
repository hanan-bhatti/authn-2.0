/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/two_factor_method.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the TwoFactorMethod entity. Stores
 *              user 2FA authenticators (TOTP, WebAuthn Passkeys, Push, Backup Codes).
 *
 * Security Notice:
 *   - TOTP secrets and backup codes are stored encrypted via KMS AES-256-GCM.
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

// TwoFactorMethod holds the schema definition for the TwoFactorMethod entity.
type TwoFactorMethod struct {
	ent.Schema
}

// Fields of the TwoFactorMethod.
func (TwoFactorMethod) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique 2FA Method ID identifier (e.g. tfm_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.Enum("type").
			Values("push", "passkey", "totp", "sms", "backup_code").
			Comment("2FA method type"),
		field.String("name").
			Optional().
			Comment("Friendly label for 2FA method (e.g. Work YubiKey 5C)"),
		field.String("secret_encrypted").
			Optional().
			Sensitive().
			Comment("AES-256-GCM encrypted TOTP secret, Argon2id hashed recovery code, or AES-256-GCM encrypted phone number for PII privacy protection (type=sms). Unused/NULL for type=passkey"),
		field.String("credential_id").
			Optional().
			Comment("WebAuthn Passkey credential ID or device identifier"),
		field.Bytes("public_key").
			Optional().
			Comment("WebAuthn COSE public key bytes"),
		field.Uint32("sign_count").
			Default(0).
			Comment("WebAuthn signature counter for clone detection"),
		field.JSON("webauthn_metadata", map[string]interface{}{}).
			Optional().
			Comment("WebAuthn metadata (AAGUID, attestation type, flags, transports)"),
		field.Bool("is_enabled").
			Default(true).
			Comment("Flag indicating if this 2FA method is active"),
		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Timestamp when 2FA method was last used for verification"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
	}
}

// Edges of the TwoFactorMethod.
func (TwoFactorMethod) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("two_factor_methods").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the TwoFactorMethod.
func (TwoFactorMethod) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "type"),
	}
}
