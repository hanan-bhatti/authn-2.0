/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/tenant_resolver.go
 * Tier: Internal Feature Package / SAML Tenant Resolution
 *
 * Resolves which tenant an unauthenticated SAML protocol request belongs to.
 *
 * Two SAML endpoints carry no Authn credential and so reach no authentication
 * middleware: the identity provider fetches SP metadata before any user exists,
 * and it POSTs the assertion to the ACS endpoint from the user's browser. Both
 * are addressed by SAML's own identifiers — an organization ID in the metadata
 * path, an IdP entity ID inside the assertion — and neither can be scoped to a
 * tenant until that identifier has been looked up.
 *
 * That lookup is the one thing here that runs unscoped, under the same bounded
 * bypass the API key lookup uses: it reads a single row to learn which tenant
 * the request belongs to, returns only that tenant's ID, and every subsequent
 * query runs scoped to it. Substituting a default tenant instead — which is
 * what this code did before — silently served one tenant's SAML configuration
 * to a request naming another's.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"context"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// ResolveTenantByOrganization returns the tenant owning organizationID.
//
// It serves the SP metadata endpoint, which is fetched by an identity provider
// that holds no Authn credential and identifies the organization by ID alone.
//
// The query runs under a bypass because the tenant is precisely what is being
// determined; it is confined to one organization ID and yields nothing but that
// organization's tenant. Callers must use the returned ID to scope everything
// they do next rather than continuing under the bypass.
//
// Returns ErrSAMLNotFound when no such organization exists, so an unknown ID is
// answered as a missing configuration rather than disclosing the difference.
func (s *Service) ResolveTenantByOrganization(ctx context.Context, organizationID string) (string, error) {
	if organizationID == "" {
		return "", ErrSAMLNotFound
	}

	sysCtx := privacy.NewBypassContext(ctx)
	org, err := s.factory.GetClient(sysCtx, "", "").Organization.Query().
		Where(organization.ID(organizationID)).
		Only(sysCtx)
	if err != nil {
		if ent.IsNotFound(err) {
			return "", ErrSAMLNotFound
		}
		return "", fmt.Errorf("failed resolving tenant for organization %s: %w", organizationID, err)
	}
	return org.TenantID, nil
}

// ResolveTenantByIssuer returns the tenant whose SAML connection declares
// idpEntityID as its identity provider.
//
// It serves the ACS endpoint, where the assertion arrives from the user's
// browser with no Authn credential attached. The issuer is read from unverified
// XML, so it is a lookup key and nothing more: it selects which tenant and
// which certificate the assertion is then checked against, and grants no
// authority by itself. Signature verification against that tenant's configured
// certificate happens downstream and is what actually authenticates the
// assertion.
//
// Returns ErrInvalidAssertion when no connection matches, keeping an unknown
// issuer indistinguishable from a malformed assertion.
func (s *Service) ResolveTenantByIssuer(ctx context.Context, idpEntityID string) (string, error) {
	if idpEntityID == "" {
		return "", ErrInvalidAssertion
	}

	sysCtx := privacy.NewBypassContext(ctx)
	conn, err := s.factory.GetClient(sysCtx, "", "").SAMLConnection.Query().
		Where(samlconnection.IdpEntityID(idpEntityID)).
		WithOrganization().
		Only(sysCtx)
	if err != nil {
		return "", fmt.Errorf("%w: no SAML connection matches the asserted issuer", ErrInvalidAssertion)
	}
	if conn.Edges.Organization == nil {
		return "", fmt.Errorf("%w: SAML connection has no owning organization", ErrInvalidAssertion)
	}
	return conn.Edges.Organization.TenantID, nil
}
