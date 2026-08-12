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
	"errors"
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
)

// CreateSAMLConnection configures SAML SSO for an organization.
//
// A domain may back at most one connection per tenant: two connections claiming
// the same domain would make the identity provider that receives a given user
// ambiguous, so an overlap is refused rather than resolved by ordering.
//
// Returns ErrSAMLExists when the organization already has a connection,
// ErrDomainConflict when a domain is taken, a validation sentinel for malformed
// input, or a wrapped storage error.
func (s *Service) CreateSAMLConnection(ctx context.Context, tenantID, actorID string, req CreateSAMLRequest, ip, userAgent string) (*SAMLConnectionResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(req.OrganizationID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("organization not found")
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
		SetEnforceSSO(req.EnforceSSO)

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
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "saml.connection_created", map[string]interface{}{
			"saml_id":         samlID,
			"org_id":          req.OrganizationID,
			"org_name":        o.Name,
			"allowed_domains": req.AllowedDomains,
			"enforce_sso":     req.EnforceSSO,
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
// Returns ErrSAMLNotFound when none is configured, ErrDomainConflict when a new
// domain is taken, a validation sentinel for malformed input, or a wrapped
// storage error.
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

	updated, err := updater.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update SAML connection: %w", err)
	}

	s.logAudit(ctx, tenantID, actorID, "saml.connection_updated", "saml_connection", conn.ID, map[string]interface{}{
		"org_id": orgID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "saml.connection_updated", map[string]interface{}{
			"saml_id": conn.ID,
			"org_id":  orgID,
		})
	}

	return s.toSAMLResponse(updated), nil
}

// DeleteSAMLConnection removes an organization's SAML configuration, which
// releases its domains for use by another connection.
//
// Returns ErrSAMLNotFound when none is configured, or a wrapped storage error.
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

	if err := client.SAMLConnection.DeleteOne(conn).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete SAML connection: %w", err)
	}

	s.logAudit(ctx, tenantID, actorID, "saml.connection_deleted", "saml_connection", conn.ID, map[string]interface{}{
		"org_id": orgID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "saml.connection_deleted", map[string]interface{}{
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
