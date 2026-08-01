/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/audit_log.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the AuditLog entity. Stores immutable
 *              security audit trail records for logins, revocations, and admin actions.
 *
 * Security Notice:
 *   - User ID is set to NULL on GDPR account deletion to preserve audit compliance.
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

// AuditLog holds the schema definition for the AuditLog entity.
type AuditLog struct {
	ent.Schema
}

// Fields of the AuditLog.
func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Audit Log ID identifier (e.g. log_1a2b3c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.String("application_id").
			Optional().
			Nillable().
			Comment("Associated Application ID"),
		field.String("user_id").
			Optional().
			Nillable().
			Comment("Associated User ID (Nullable on GDPR account deletion)"),
		field.String("event_type").
			NotEmpty().
			Comment("Event type string (e.g. user.login.success, 2fa.verified, user.impersonated)"),
		field.String("ip_address").
			Optional().
			Comment("Client IP address"),
		field.String("user_agent").
			Optional().
			Comment("Client HTTP User-Agent header string"),
		field.JSON("metadata", map[string]interface{}{}).
			Optional().
			Comment("Structured JSON metadata payload for event context"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Audit log timestamp"),
	}
}

// Edges of the AuditLog.
func (AuditLog) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("audit_logs").
			Field("tenant_id").
			Unique().
			Required(),
	}
}

// Indexes of the AuditLog.
func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "created_at"),
		index.Fields("user_id"),
		index.Fields("event_type"),
	}
}
