/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/session_app_activity.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the SessionAppActivity entity.
 *              Records when a shared session was last used at each application
 *              under the tenant.
 *
 * A session belongs to the tenant, not to one application: signing in once at
 * the dashboard also signs the user in at the docs site, and revoking that
 * session signs them out of both. What the session itself cannot express is
 * where it has been used, so "last active" on a tenant-wide session says only
 * that some app saw traffic. These rows carry that detail per application,
 * without splitting the session or making revocation partial.
 *
 * One row per (session, application) pair, created on first use and touched
 * afterwards. Lifetime is the session's: the rows are deleted with it.
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

// SessionAppActivity holds the schema definition for the SessionAppActivity entity.
type SessionAppActivity struct {
	ent.Schema
}

// Fields of the SessionAppActivity.
func (SessionAppActivity) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique Session App Activity ID identifier (e.g. saa_1a2b3c)"),
		field.String("session_id").
			NotEmpty().
			Comment("Session this activity belongs to. Re-pointed at the successor when a refresh rotates the session, so activity follows the login rather than restarting every rotation"),
		field.String("application_id").
			NotEmpty().
			Immutable().
			Comment("Application the session was used at"),
		field.Time("first_seen_at").
			Default(time.Now).
			Immutable().
			Comment("Timestamp when this session was first used at this application"),
		field.Time("last_active_at").
			Default(time.Now).
			Comment("Timestamp when this session was most recently used at this application"),
	}
}

// Edges of the SessionAppActivity.
func (SessionAppActivity) Edges() []ent.Edge {
	return []ent.Edge{
		// Both parents delete their activity rows with them. The cascade is
		// declared on the parent schemas — Session.app_activity and
		// Application.session_activity — because that is the side codegen reads
		// when it emits the foreign key.
		edge.From("session", Session.Type).
			Ref("app_activity").
			Field("session_id").
			Unique().
			Required(),
		edge.From("application", Application.Type).
			Ref("session_activity").
			Field("application_id").
			Unique().
			Required().
			Immutable(),
	}
}

// Indexes of the SessionAppActivity.
func (SessionAppActivity) Indexes() []ent.Index {
	return []ent.Index{
		// The pair is the identity of the row. Unique because every write is an
		// upsert on it — without the constraint, two concurrent requests from the
		// same session both insert and the app accumulates duplicate rows whose
		// timestamps each tell half the story.
		index.Fields("session_id", "application_id").Unique(),
		// Serves "which sessions have been active at this app recently", the read
		// this entity exists to answer.
		index.Fields("application_id", "last_active_at"),
	}
}
