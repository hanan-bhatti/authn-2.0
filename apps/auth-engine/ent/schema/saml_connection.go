/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/ent/schema/saml_connection.go
 * Tier: Database Persistence Layer / Ent ORM Schema
 *
 * Description: Ent ORM schema definition for the SAMLConnection entity. Stores Enterprise
 *              SAML 2.0 Identity Provider (IdP) metadata, X.509 certificate, allowed domains,
 *              attribute mappings, and enforcement settings per Organization.
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

// SAMLConnection holds the schema definition for the SAMLConnection entity.
type SAMLConnection struct {
	ent.Schema
}

// Fields of the SAMLConnection.
func (SAMLConnection) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			StorageKey("id").
			Unique().
			Immutable().
			Comment("Unique SAML Connection ID identifier (e.g. saml_1a2b3c)"),
		field.String("organization_id").
			NotEmpty().
			Comment("Owning Organization ID"),
		field.String("idp_entity_id").
			NotEmpty().
			Comment("SAML Identity Provider Entity ID / Issuer URI"),
		field.String("idp_sso_url").
			NotEmpty().
			Comment("SAML Identity Provider Single Sign-On HTTP-POST / Redirect URL"),
		field.String("idp_certificate").
			NotEmpty().
			Comment("Public X.509 PEM certificate used for verifying SAML assertion XML signatures"),
		field.Strings("allowed_domains").
			Comment("Array of verified email domains associated with this SAML connection (e.g. ['siemens.com', 'siemens.de'])"),
		field.JSON("attribute_mapping", map[string]string{}).
			Optional().
			Comment("JSON mapping of SAML assertion attribute names to Authn user fields"),
		field.Bool("enforce_sso").
			Default(false).
			Comment("Flag indicating if password and social logins are strictly disabled for allowed domains"),
		field.Time("created_at").
			Default(time.Now).
			Immutable().
			Comment("Creation timestamp"),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Comment("Last update timestamp"),
	}
}

// Edges of the SAMLConnection.
func (SAMLConnection) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("organization", Organization.Type).
			Ref("saml_connections").
			Field("organization_id").
			Unique().
			Required(),
	}
}

// Indexes of the SAMLConnection.
func (SAMLConnection) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("organization_id"),
	}
}
