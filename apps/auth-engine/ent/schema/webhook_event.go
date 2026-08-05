/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/webhook_event.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the WebhookEvent entity. Logs HTTP
 *              webhook dispatch attempts, status codes, and payloads.
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

// WebhookEvent holds the schema definition for the WebhookEvent entity.
type WebhookEvent struct {
	ent.Schema
}

// Fields of the WebhookEvent.
func (WebhookEvent) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Webhook Event ID identifier (e.g. whev_1a2b3c)"),
		field.String("webhook_endpoint_id").
			NotEmpty().
			Comment("Target Webhook Endpoint ID"),
		field.String("event_type").
			NotEmpty().
			Comment("Event type string (e.g. user.created, session.revoked)"),
		field.JSON("payload", map[string]interface{}{}).
			Comment("Dispatched JSON payload"),
		field.Int("status_code").
			Optional().
			Comment("HTTP status code received from target server (e.g. 200, 500)"),
		field.String("response_body").
			Optional().
			Comment("Snippet of HTTP response body returned by target server for developer debugging"),
		field.String("error_message").
			Optional().
			Comment("Network connection or execution error traceback message"),
		field.Enum("status").
			Values("success", "failed").
			Comment("Dispatch status: success or failed"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Dispatch timestamp"),
	}
}

// Edges of the WebhookEvent.
func (WebhookEvent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("webhook_endpoint", WebhookEndpoint.Type).
			Ref("events").
			Field("webhook_endpoint_id").
			Unique().
			Required().
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
	}
}

// Indexes of the WebhookEvent.
func (WebhookEvent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("webhook_endpoint_id", "status"),
		index.Fields("created_at"),
	}
}
