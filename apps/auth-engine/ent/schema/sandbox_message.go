/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/sandbox_message.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the SandboxMessage entity. Stores an
 *              email or SMS that the test environment captured instead of sending,
 *              so a sign-in flow can be exercised end to end without delivering to
 *              a real inbox or handset.
 *
 * Security Notice:
 *   - Rows hold one-time codes and recovery links in plain text, which is the point
 *     of the entity: a test harness has to read them. Only ever written in the test
 *     environment, and confined to the owning tenant by the privacy interceptor.
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

// SandboxMessage holds the schema definition for the SandboxMessage entity.
//
// The test environment captures outbound messages here rather than dispatching
// them. That answers "is my template right, and what code did it contain" without
// a mailbox, and without emailing a real person who never signed up for anything.
//
// It deliberately does not answer "do my provider credentials work" — a captured
// message never touches the provider, so proving delivery needs a real send. That
// is a separate, deliberately narrow path; see the provider verification endpoint.
type SandboxMessage struct {
	ent.Schema
}

// Fields of the SandboxMessage.
func (SandboxMessage) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Sandbox Message ID identifier (e.g. sbxmsg_1a2b3c)"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID"),
		field.Enum("environment").
			Values("test", "live").
			Default("test").
			Immutable().
			Comment("Environment the message was captured in. Only test rows are ever written; the field exists so this entity is narrowed by the same predicate as every other environment-scoped one, which means a live-key query cannot read sandbox traffic even if a row were somehow written as live."),
		field.Enum("channel").
			Values("email", "sms").
			Immutable().
			Comment("Which transport would have carried the message"),
		field.String("recipient").
			NotEmpty().
			Comment("Address the message was addressed to: an email address, or an E.164 phone number for SMS"),
		field.String("subject").
			Optional().
			Comment("Rendered subject line. Empty for SMS, which has none."),
		field.Text("body").
			Comment("Fully rendered message body, exactly as the provider would have received it"),
		field.String("template").
			Optional().
			Comment("Identifier of the template that produced the body (e.g. email_verification), for a harness that wants to assert on which message was triggered rather than parse the body"),
		field.String("code").
			Optional().
			Comment("The one-time code carried by the message, lifted out at capture time. Present so an automated test can complete a verification flow without parsing rendered HTML; empty for messages that carry no code."),
		field.JSON("metadata", map[string]interface{}{}).
			Optional().
			Comment("Template variables and any structured values the sender attached, such as an action link"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("When the message was captured"),
	}
}

// Edges of the SandboxMessage.
func (SandboxMessage) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("sandbox_messages").
			Field("tenant_id").
			Unique().
			Required(),
	}
}

// Indexes of the SandboxMessage.
func (SandboxMessage) Indexes() []ent.Index {
	return []ent.Index{
		// The inbox is read newest-first for one tenant's environment, and swept by
		// age; both are served by this ordering.
		index.Fields("tenant_id", "environment", "created_at"),
		// Polling for "the code that just went to this address" is the common harness
		// query, and it must not degrade into a scan as captured traffic accumulates.
		index.Fields("tenant_id", "recipient", "created_at"),
	}
}
