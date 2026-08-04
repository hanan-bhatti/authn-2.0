/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/recovery_request.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for RecoveryRequest entity. Implements the complete
 *              state machine for account recovery requests and the 48-hour freeze window.
 *
 * Security Notice:
 *   - Cancellation tokens and claim tokens are stored as SHA-256 hashes only.
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

// RecoveryRequest holds the schema definition for the RecoveryRequest entity.
type RecoveryRequest struct {
	ent.Schema
}

// Fields of the RecoveryRequest.
func (RecoveryRequest) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique RecoveryRequest ID identifier (e.g. req_1a2b3c)"),
		field.String("user_id").
			NotEmpty().
			Comment("Owning User ID"),
		field.String("initiated_from_ip").
			NotEmpty().
			Comment("IP address from which recovery was initiated"),
		field.String("initiated_from_subnet").
			NotEmpty().
			Comment("Subnet range (/24 or /48) of initiating IP"),
		field.String("initiated_from_user_agent").
			NotEmpty().
			Comment("User-Agent string of initiating browser/client"),
		field.Bool("is_trusted_device_origin").
			Default(false).
			Comment("Flag indicating if initiation originated from a verified trusted device + subnet"),
		field.Enum("proof_method_used").
			Values("guardian_consensus", "phone_otp", "email_otp", "old_password", "security_questions").
			Optional().
			Nillable().
			Comment("Identity-proof method selected/verified for this recovery attempt"),
		field.Enum("status").
			Values("initiated", "awaiting_proof", "proof_verified", "freeze_active", "ready_for_claim", "completed", "cancelled", "expired").
			Default("initiated").
			Comment("Current state machine status of the recovery request"),
		field.Int("submitted_shares_count").
			Default(0).
			Comment("Count of valid guardian shares collected so far"),
		field.JSON("submitted_share_indexes", []int{}).
			Optional().
			Comment("JSON array of share indexes (e.g. [1, 3]) submitted so far"),
		field.Time("freeze_started_at").
			Optional().
			Nillable().
			Comment("Timestamp when mandatory 48-hour freeze window started"),
		field.Time("freeze_expires_at").
			Optional().
			Nillable().
			Comment("Timestamp when 48-hour freeze window expires (freeze_started_at + 48h)"),
		field.String("cancellation_token_hash").
			NotEmpty().
			Sensitive().
			Comment("SHA-256 hash of signed multi-channel cancellation link token"),
		field.String("claim_token_hash").
			Optional().
			Nillable().
			Sensitive().
			Comment("SHA-256 hash of single-use 15-minute claim token issued after freeze"),
		field.Time("claim_token_expires_at").
			Optional().
			Nillable().
			Comment("Expiration timestamp of claim token (15 minutes after freeze expiration)"),
		field.Time("completed_at").
			Optional().
			Nillable().
			Comment("Timestamp when recovery was successfully completed"),
		field.Time("cancelled_at").
			Optional().
			Nillable().
			Comment("Timestamp when recovery request was cancelled by user"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Initiation timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Last state change timestamp"),
	}
}

// Edges of the RecoveryRequest.
func (RecoveryRequest) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("recovery_requests").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Indexes of the RecoveryRequest.
func (RecoveryRequest) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "status"),
		index.Fields("cancellation_token_hash").Unique(),
		index.Fields("claim_token_hash"),
		index.Fields("freeze_expires_at"),
	}
}
