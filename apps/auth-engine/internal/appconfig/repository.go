/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/appconfig/repository.go
 * Tier: Internal Feature Package / App Config Repository
 *
 * Reads the two things behind a sign-in page that do not live on the tenant's
 * per-environment settings row: the workspace's public identity, and whether it has
 * an enterprise connection to offer.
 *
 * Everything a customer can configure per environment — branding, social providers,
 * every policy — is owned by internal/policy and read through it. What stays here is
 * what a tenant has exactly one of, regardless of which key is asking.
 *
 * Reads never fail the caller. This sits on the very first request a sign-in page
 * makes, so an unreadable row yields an unnamed workspace and no SSO button — an
 * unstyled page that still signs users in — rather than a page that cannot render at
 * all. The failure is logged, because unlike a missing policy an unreadable tenant
 * row is always a fault rather than a legitimate unconfigured state.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package appconfig

import (
	"context"
	"encoding/json"
	"log"
	"sort"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// tenantPoolEnvironment is the environment passed when selecting a connection pool
// for the tenant-row read. A tenant has one identity across both environments, so
// this selects a pool and nothing else.
const tenantPoolEnvironment = "test"

// TenantIdentity is the workspace's public name, as a sign-in page displays it.
//
// It is not environment-scoped: a customer's test and live sign-in pages belong to
// the same workspace and say the same name.
type TenantIdentity struct {
	Name string
	Slug string
}

// Repository reads the tenant row's public identity and probes for enterprise
// connections.
type Repository struct {
	// factory produces the ORM client for the tenant being read.
	factory *clientfactory.ClientFactory
}

// NewRepository returns a repository backed by the given client factory.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// TenantIdentity returns the tenant's public name and slug.
//
// It never returns an error: a missing or unreadable row yields zero values, which
// renders a page with no workspace name rather than no page.
func (r *Repository) TenantIdentity(ctx context.Context, tenantID string) TenantIdentity {
	client := r.factory.GetClient(ctx, tenantID, tenantPoolEnvironment)

	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		log.Printf("[error] appconfig.tenant_identity tenant=%s: %v", tenantID, err)
		return TenantIdentity{}
	}

	return TenantIdentity{Name: t.Name, Slug: t.Slug}
}

// HasEnterpriseSSO reports whether the tenant has at least one SAML connection
// provisioning users into this environment.
//
// The environment predicate is written out here rather than left to the privacy
// interceptor, which does not narrow SAML connections by environment: the assertion
// consumer endpoint resolves a connection from the identity provider's response
// alone, with no key and so no environment to scope by, and an interceptor
// predicate would make live connections invisible to it. A bootstrap request does
// have an environment, and offering a test page a button that provisions live
// accounts is the outcome worth preventing.
//
// The tenant predicate is left to the interceptor, which narrows connections to
// those whose organization belongs to the context's tenant — so the scope comes from
// the credential that opened the request. An unreadable table reports false, hiding
// an SSO button the tenant has rather than offering one it lacks.
func (r *Repository) HasEnterpriseSSO(ctx context.Context, tenantID, environment string) bool {
	client := r.factory.GetClient(ctx, tenantID, environment)

	exists, err := client.SAMLConnection.Query().
		Where(samlconnection.EnvironmentEQ(samlconnection.Environment(environment))).
		Exist(ctx)
	if err != nil {
		log.Printf("[error] appconfig.has_enterprise_sso tenant=%s environment=%s: %v", tenantID, environment, err)
		return false
	}
	return exists
}

// decodeBranding narrows the stored JSON column to the public branding fields.
//
// The round trip through Branding is what makes the column safe to serve: the
// stored object is free-form and shared with settings that are not public, and
// unmarshalling into a fixed struct silently drops every key the struct does not
// name. A column that fails to parse yields the default branding rather than a
// partial one.
func decodeBranding(stored map[string]interface{}) Branding {
	if len(stored) == 0 {
		return DefaultBranding()
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return DefaultBranding()
	}

	var b Branding
	if err := json.Unmarshal(data, &b); err != nil {
		return DefaultBranding()
	}
	return b
}

// encodeBranding renders validated branding as the free-form column it is stored
// in. The value has already been through ValidateBranding, so marshalling cannot
// fail on it.
func encodeBranding(b Branding) map[string]interface{} {
	var stored map[string]interface{}
	data, _ := json.Marshal(b)
	_ = json.Unmarshal(data, &stored)
	return stored
}

// enabledProviders returns the sorted names of the social providers a tenant has
// switched on.
//
// Only the "enabled" flag is read. The stored entry alongside it holds the
// provider's client ID and the ciphertext of its client secret, and neither is
// decoded here — a value that is never read cannot be leaked by a later change to
// how this result is serialised.
//
// An entry that does not decode is skipped rather than failing the read, so one
// malformed provider cannot blank out a tenant's whole sign-in page.
func enabledProviders(stored map[string]interface{}) []string {
	names := make([]string, 0, len(stored))
	for name, raw := range stored {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if enabled, ok := entry["enabled"].(bool); ok && enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
