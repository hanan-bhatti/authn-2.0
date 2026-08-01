/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/push_device.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the PushDevice entity. Stores FCM (Android)
 *              and APNs (iOS) push notification device tokens for Push 2FA.
 *
 * Security Notice:
 *   - Device tokens are bound to authenticated user KeyStore/Secure Enclave keys.
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

// PushDevice holds the schema definition for the PushDevice entity.
type PushDevice struct {
	ent.Schema
}

// Fields of the PushDevice.
func (PushDevice) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Push Device ID identifier (e.g. dev_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.Enum("platform").
			Values("android", "ios").
			Comment("Mobile platform: android (FCM) or ios (APNs)"),
		field.String("device_token").
			Unique().
			NotEmpty().
			Comment("FCM registration token or APNs device token string"),
		field.String("public_key_pem").
			NotEmpty().
			Comment("PEM-encoded public key generated in mobile KeyStore/Secure Enclave"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Registration timestamp"),
	}
}

// Edges of the PushDevice.
func (PushDevice) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("push_devices").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the PushDevice.
func (PushDevice) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("device_token").Unique(),
		index.Fields("user_id"),
	}
}
