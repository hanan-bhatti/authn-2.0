/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/saml_config_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: SP metadata helpers and IdP connection configuration CRUD operations.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"context"
	"fmt"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// callerMayWrite reports whether the scope on ctx permits a write that leaves a
// connection in, or finds one already in, environment env.
//
// A connection in test is a trial and anyone configuring the organization may
// change it. A connection in live is the record an organization's real employees
// authenticate through, so its certificate, its SSO URL and its existence are
// live configuration: a test credential can neither edit one nor promote a trial
// into one. Without this the environment on the connection would be an ordinary
// request field, and a test key could file a live connection by supplying nothing
// at all — the schema default for this entity is live.
//
// The reverse crossing is allowed. A live key may edit a connection still in
// test, which is what a promotion has to read before it writes.
//
// A context carrying no scope, or a bypass, is exempt: provisioning, seeding and
// the retention sweeps address both environments at once, and every HTTP entry
// point installs a scope, so an absent one is not a request.
func callerMayWrite(ctx context.Context, env samlconnection.Environment) bool {
	if env != samlconnection.EnvironmentLive {
		return true
	}

	p, ok := privacy.FromContext(ctx)
	if !ok || p.Bypass || p.Environment == "" {
		return true
	}
	return p.Environment == string(samlconnection.EnvironmentLive)
}

// CreateSAMLConnection configures SAML SSO for an organization.
//
// A domain may back at most one connection per tenant: two connections claiming
// the same domain would make the identity provider that receives a given user
// ambiguous, so an overlap is refused rather than resolved by ordering.
//
// req.Environment decides where the people arriving through the provider are
// provisioned, and an omitted value means live. It is carried on the connection
// rather than derived from the caller's key because an organization has one
// connection, so the same record has to be able to move from a trial into
// production without being deleted and rebuilt.
//
// Because the default is live, filing a connection is by default a live act:
// naming live, or naming nothing, takes a live credential.
//
// Returns ErrSAMLExists when the organization already has a connection,
// ErrDomainConflict when a domain is taken, ErrLiveKeyRequired when a test
// credential asks for a live connection, a validation sentinel for malformed
// input, or a wrapped storage error.
func (s *Service) CreateSAMLConnection(ctx context.Context, tenantID, actorID string, req CreateSAMLRequest, ip, userAgent string) (*SAMLConnectionResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// Checked after Validate, which is where an omitted environment becomes the
	// schema default. Checked before the organization lookup so a test key learns
	// it holds the wrong credential rather than whether the organization exists.
	if !callerMayWrite(ctx, samlconnection.Environment(req.Environment)) {
		return nil, ErrLiveKeyRequired
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(req.OrganizationID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("failed to query organization: %w", err)
	}

	exists, err := client.SAMLConnection.Query().
		Where(samlconnection.OrganizationID(req.OrganizationID)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing SAML connection: %w", err)
	}
	if exists {
		return nil, ErrSAMLExists
	}

	allConns, err := client.SAMLConnection.Query().All(ctx)
	if err == nil {
		for _, conn := range allConns {
			for _, newDom := range req.AllowedDomains {
				for _, existingDom := range conn.AllowedDomains {
					if strings.EqualFold(newDom, existingDom) {
						return nil, fmt.Errorf("%w: domain '%s' is already mapped", ErrDomainConflict, newDom)
					}
				}
			}
		}
	}

	samlID := idgen.New("saml")

	builder := client.SAMLConnection.Create().
		SetID(samlID).
		SetOrganizationID(req.OrganizationID).
		SetIdpEntityID(req.IDPEntityID).
		SetIdpSSOURL(req.IDPSSOURL).
		SetIdpCertificate(req.IDPCertificate).
		SetAllowedDomains(req.AllowedDomains).
		SetEnforceSSO(req.EnforceSSO).
		SetEnvironment(samlconnection.Environment(req.Environment))

	if req.AttributeMapping != nil {
		builder.SetAttributeMapping(req.AttributeMapping)
	}

	created, err := builder.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to save SAML connection: %w", err)
	}

	s.logAudit(ctx, tenantID, actorID, "saml.connection_created", "saml_connection", samlID, map[string]interface{}{
		"org_id":          req.OrganizationID,
		"allowed_domains": req.AllowedDomains,
		"enforce_sso":     req.EnforceSSO,
		"environment":     req.Environment,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, string(created.Environment), "saml.connection_created", map[string]interface{}{
			"saml_id":         samlID,
			"org_id":          req.OrganizationID,
			"org_name":        o.Name,
			"allowed_domains": req.AllowedDomains,
			"enforce_sso":     req.EnforceSSO,
			"environment":     req.Environment,
		})
	}

	return s.toSAMLResponse(created), nil
}

// GetSAMLConnection returns the SAML configuration for an organization.
//
// Returns ErrSAMLNotFound when none is configured, or a wrapped storage error.
func (s *Service) GetSAMLConnection(ctx context.Context, tenantID, orgID string) (*SAMLConnectionResponse, error) {
	client := s.factory.GetClient(ctx, tenantID, "")

	conn, err := client.SAMLConnection.Query().
		Where(samlconnection.OrganizationID(orgID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSAMLNotFound
		}
		return nil, fmt.Errorf("failed to query SAML connection: %w", err)
	}

	return s.toSAMLResponse(conn), nil
}

// UpdateSAMLConnection applies the supplied fields to an organization's
// connection, leaving omitted fields unchanged.
//
// Replacing the domain list re-runs the tenant-wide exclusivity check against
// every other connection.
//
// Supplying environment promotes or demotes the connection, which is what makes
// trialling a provider useful. It changes where subsequent sign-ins are
// provisioned and leaves the accounts already created where they are; see
// UpdateSAMLRequest.Environment.
//
// Both sides of that move are guarded: a test credential can neither edit a
// connection already in live nor promote one into it, so the only caller that can
// put an identity provider in front of real employees is the one holding the live
// key.
//
// Returns ErrSAMLNotFound when none is configured, ErrDomainConflict when a new
// domain is taken, ErrLiveKeyRequired when a test credential addresses a live
// connection, a validation sentinel for malformed input, or a wrapped storage
// error.
func (s *Service) UpdateSAMLConnection(ctx context.Context, tenantID, actorID, orgID string, req UpdateSAMLRequest, ip, userAgent string) (*SAMLConnectionResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	conn, err := client.SAMLConnection.Query().
		Where(samlconnection.OrganizationID(orgID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSAMLNotFound
		}
		return nil, fmt.Errorf("failed to query SAML connection: %w", err)
	}

	// The stored environment and the requested one are both checked, and for
	// different reasons: the first stops a test key touching live SSO at all, the
	// second stops it promoting a trial it does own.
	if !callerMayWrite(ctx, conn.Environment) {
		return nil, ErrLiveKeyRequired
	}
	if req.Environment != nil && !callerMayWrite(ctx, samlconnection.Environment(*req.Environment)) {
		return nil, ErrLiveKeyRequired
	}

	updater := conn.Update()

	if req.IDPEntityID != nil {
		updater.SetIdpEntityID(*req.IDPEntityID)
	}
	if req.IDPSSOURL != nil {
		updater.SetIdpSSOURL(*req.IDPSSOURL)
	}
	if req.IDPCertificate != nil {
		updater.SetIdpCertificate(*req.IDPCertificate)
	}
	if req.AllowedDomains != nil {
		// This connection is excluded from the conflict scan so that keeping a
		// domain it already owns is not treated as a collision with itself.
		allConns, err := client.SAMLConnection.Query().
			Where(samlconnection.IDNEQ(conn.ID)).
			All(ctx)
		if err == nil {
			for _, existingConn := range allConns {
				for _, newDom := range req.AllowedDomains {
					for _, existingDom := range existingConn.AllowedDomains {
						if strings.EqualFold(newDom, existingDom) {
							return nil, fmt.Errorf("%w: domain '%s' is already mapped", ErrDomainConflict, newDom)
						}
					}
				}
			}
		}
		updater.SetAllowedDomains(req.AllowedDomains)
	}
	if req.AttributeMapping != nil {
		updater.SetAttributeMapping(req.AttributeMapping)
	}
	if req.EnforceSSO != nil {
		updater.SetEnforceSSO(*req.EnforceSSO)
	}
	if req.Environment != nil {
		updater.SetEnvironment(samlconnection.Environment(*req.Environment))
	}

	updated, err := updater.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update SAML connection: %w", err)
	}

	// The environment is recorded on both sides of the change, because promoting a
	// connection out of test is the edit that decides whether an identity provider
	// starts minting real accounts, and "when did this go live" needs an answer
	// that does not depend on reading the current row.
	metadata := map[string]interface{}{
		"org_id": orgID,
	}
	if req.Environment != nil && *req.Environment != string(conn.Environment) {
		metadata["environment_from"] = string(conn.Environment)
		metadata["environment_to"] = *req.Environment
	}

	s.logAudit(ctx, tenantID, actorID, "saml.connection_updated", "saml_connection", conn.ID, metadata, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, string(updated.Environment), "saml.connection_updated", map[string]interface{}{
			"saml_id": conn.ID,
			"org_id":  orgID,
		})
	}

	return s.toSAMLResponse(updated), nil
}

// DeleteSAMLConnection removes an organization's SAML configuration, which
// releases its domains for use by another connection.
//
// Returns ErrSAMLNotFound when none is configured, ErrLiveKeyRequired when a test
// credential addresses a live connection, or a wrapped storage error.
func (s *Service) DeleteSAMLConnection(ctx context.Context, tenantID, actorID, orgID string, ip, userAgent string) error {
	client := s.factory.GetClient(ctx, tenantID, "")

	conn, err := client.SAMLConnection.Query().
		Where(samlconnection.OrganizationID(orgID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSAMLNotFound
		}
		return fmt.Errorf("failed to query SAML connection: %w", err)
	}

	// Deleting a live connection locks every employee out of the organization, so
	// it is the same live act as configuring one.
	if !callerMayWrite(ctx, conn.Environment) {
		return ErrLiveKeyRequired
	}

	if err := client.SAMLConnection.DeleteOne(conn).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete SAML connection: %w", err)
	}

	s.logAudit(ctx, tenantID, actorID, "saml.connection_deleted", "saml_connection", conn.ID, map[string]interface{}{
		"org_id": orgID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, string(conn.Environment), "saml.connection_deleted", map[string]interface{}{
			"saml_id": conn.ID,
			"org_id":  orgID,
		})
	}

	return nil
}

// LookupDomainSSO resolves an email domain to the SAML connection that claims
// it, so a sign-in page can route the user before asking for a password.
//
// EnforceSSO in the result tells the caller whether password and social sign-in
// must be refused for this domain rather than merely offered alongside SSO.
//
// Returns a response with HasSSO false when no connection claims the domain, a
// validation error for an unusable request, or a wrapped storage error.
func (s *Service) LookupDomainSSO(ctx context.Context, tenantID string, req DomainLookupRequest) (*DomainLookupResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	allConns, err := client.SAMLConnection.Query().
		WithOrganization().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query SAML connections: %w", err)
	}

	for _, conn := range allConns {
		for _, d := range conn.AllowedDomains {
			if strings.EqualFold(d, req.Domain) {
				orgName := ""
				if conn.Edges.Organization != nil {
					orgName = conn.Edges.Organization.Name
				}
				return &DomainLookupResponse{
					HasSSO:     true,
					EnforceSSO: conn.EnforceSSO,
					OrgID:      conn.OrganizationID,
					OrgName:    orgName,
					IDPSSOURL:  conn.IdpSSOURL,
				}, nil
			}
		}
	}

	return &DomainLookupResponse{HasSSO: false, EnforceSSO: false}, nil
}
