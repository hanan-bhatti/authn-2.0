/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/webhook_endpoint.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the WebhookEndpoint entity. Stores
 *              developer-configured HTTP webhook listeners.
 *
 * Security Notice:
 *   - Webhook HMAC secret keys are encrypted using AES-256-GCM.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// WebhookEndpoint holds the schema definition for the WebhookEndpoint entity.
type WebhookEndpoint struct {
	ent.Schema
}

// Fields of the WebhookEndpoint.
func (WebhookEndpoint) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Webhook Endpoint ID identifier (e.g. whe_1a2b3c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.String("url").
			NotEmpty().
			Comment("Target HTTP webhook listener URL"),
		field.String("description").
			Optional().
			Comment("Optional friendly description for webhook endpoint"),
		field.String("secret_key_encrypted").
			Sensitive().
			NotEmpty().
			Comment("AES-256-GCM encrypted secret key used for HMAC-SHA256 event payload signing"),
		field.String("secret_key_hash").
			Optional().
			Unique().
			Comment("SHA-256 digest of secret key to guarantee uniqueness and prevent collisions"),
		field.Strings("subscribed_events").
			Comment("Subscribed event type array (e.g. user.created, session.revoked, 2fa.enabled)"),
		field.Bool("is_active").
			Default(true).
			Comment("Flag indicating if the webhook endpoint is active"),
		field.Int("failure_count").
			Default(0).
			Comment("Consecutive failure count used for auto-disabling broken endpoints"),
		field.Time("last_triggered_at").
			Optional().
			Nillable().
			Comment("Timestamp when event was last dispatched to this endpoint"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
	}
}

// Edges of the WebhookEndpoint.
func (WebhookEndpoint) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("webhook_endpoints").
			Field("tenant_id").
			Unique().
			Required(),
		// Dispatch history, deleted with the endpoint. Nothing in the engine
		// clears these rows by hand, so without the cascade a delete is refused
		// by the foreign key as soon as the endpoint has ever fired.
		edge.To("events", WebhookEvent.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes of the WebhookEndpoint.
func (WebhookEndpoint) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "is_active"),
	}
}
