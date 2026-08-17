/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/social_auth_state.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the SocialAuthState entity.
 *              Stores short-lived CSRF state tokens for OAuth2 social login flows.
 *
 *              Flow:
 *                1. GET /v1/client/auth/social/:provider/authorize
 *                   → generates 32-byte random state, persists here (10 min TTL)
 *                   → redirects browser to provider with state param
 *                2. Provider redirects back to /v1/client/auth/social/:provider/callback
 *                   → server looks up state, validates, DELETES (one-use only)
 *                   → proceeds with token exchange
 *
 *              Without this entity an attacker can forge a callback URL with an
 *              arbitrary code and hijack another user's session (CSRF on OAuth).
 *
 *              Records are hard-deleted on use. Expired records are purged by a
 *              background goroutine (same pattern as trusted_device expiry purge).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// SocialAuthState holds the schema definition for the SocialAuthState entity.
type SocialAuthState struct {
	ent.Schema
}

// Fields of the SocialAuthState.
func (SocialAuthState) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("The state token itself — 32 random hex bytes used as the primary key and CSRF nonce"),
		field.String("tenant_id").
			NotEmpty().
			Comment("Owning Tenant ID — scopes the callback lookup to the correct tenant"),
		field.String("application_id").
			NotEmpty().
			Comment("Application ID that initiated the social login request"),
		field.String("environment").
			NotEmpty().
			Comment("Environment mode: test or live — must match the pk_ key used"),
		field.String("provider").
			NotEmpty().
			Comment("Social provider name (google, github, discord, microsoft, apple, facebook, x, linkedin, oidc)"),
		field.String("redirect_uri").
			NotEmpty().
			Comment("Client-supplied redirect URI — validated against application.exact_redirect_uris, returned to client after successful callback"),
		field.String("post_callback_redirect").
			Optional().
			Comment("Optional deep-link URL to redirect to after our callback completes (e.g. the SPA page that triggered the flow)"),
		field.Time("expires_at").
			Comment("Expiration timestamp — 10 minutes from creation. Requests arriving after this are rejected with 400 state_expired"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("State token creation timestamp"),
	}
}

// Edges of the SocialAuthState.
// No edges — this is an ephemeral lookup-and-delete record.
// Tenant and Application are referenced by ID only to avoid FK cascade issues on purge.
func (SocialAuthState) Edges() []ent.Edge {
	return nil
}

// Indexes of the SocialAuthState.
func (SocialAuthState) Indexes() []ent.Index {
	return []ent.Index{
		// Primary lookup path: find state by token value (used in callback handler)
		index.Fields("id").Unique(),
		// Purge path: delete all expired states for a tenant efficiently
		index.Fields("tenant_id", "expires_at"),
		// The retention sweep runs across tenants, so it cannot use the composite
		// above and needs expires_at as a leading column of its own.
		index.Fields("expires_at"),
	}
}
