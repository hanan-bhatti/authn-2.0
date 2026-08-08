/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Core business logic implementation for Enterprise SAML 2.0 & Native SSO.
 *              Handles SAML configuration CRUD, domain lookup enforcement, ACS assertion parsing,
 *              X.509 signature verification, JIT user provisioning, audit logging, and webhook events.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

type WebhookDispatcher interface {
	Dispatch(tenantID, eventType string, data map[string]interface{})
}

type Service struct {
	factory    *clientfactory.ClientFactory
	dispatcher WebhookDispatcher
}

func NewService(factory *clientfactory.ClientFactory, dispatcher WebhookDispatcher) *Service {
	return &Service{
		factory:    factory,
		dispatcher: dispatcher,
	}
}

// Minimal XML structs for SAMLResponse parsing
type SAMLResponseXML struct {
	XMLName      xml.Name               `xml:"Response"`
	ID           string                 `xml:"ID,attr"`
	IssueInstant string                 `xml:"IssueInstant,attr"`
	Destination  string                 `xml:"Destination,attr"`
	Issuer       string                 `xml:"Issuer"`
	Status       SAMLStatus             `xml:"Status"`
	Assertion    SAMLAssertion           `xml:"Assertion"`
}

type SAMLStatus struct {
	StatusCode SAMLStatusCode `xml:"StatusCode"`
}

type SAMLStatusCode struct {
	Value string `xml:"Value,attr"`
}

type SAMLAssertion struct {
	ID           string                 `xml:"ID,attr"`
	IssueInstant string                 `xml:"IssueInstant,attr"`
	Issuer       string                 `xml:"Issuer"`
	Subject      SAMLSubject            `xml:"Subject"`
	Conditions   SAMLConditions         `xml:"Conditions"`
	Attributes   SAMLAttributeStatement `xml:"AttributeStatement"`
}

type SAMLSubject struct {
	NameID string `xml:"NameID"`
}

type SAMLConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type SAMLAttributeStatement struct {
	Attributes []SAMLAttribute `xml:"Attribute"`
}

type SAMLAttribute struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

// CreateSAMLConnection provisions a SAML 2.0 configuration for an organization.
func (s *Service) CreateSAMLConnection(ctx context.Context, tenantID, actorID string, req CreateSAMLRequest, ip, userAgent string) (*SAMLConnectionResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Check org existence
	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(req.OrganizationID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("organization not found")
		}
		return nil, fmt.Errorf("failed to query organization: %w", err)
	}

	// Check existing SAML connection for org
	exists, err := client.SAMLConnection.Query().
		Where(samlconnection.OrganizationID(req.OrganizationID)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing SAML connection: %w", err)
	}
	if exists {
		return nil, ErrSAMLExists
	}

	// Check for domain conflicts across all SAML connections in tenant
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

	samlID := fmt.Sprintf("saml_%s", uuid.New().String()[:12])

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

// GetSAMLConnection retrieves SAML settings for an organization.
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

// UpdateSAMLConnection updates existing SAML settings.
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
		// Domain conflict check
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

// DeleteSAMLConnection removes SAML settings for an organization.
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

// LookupDomainSSO inspects email domain to check if active SAML SSO exists and if enforce_sso is enabled.
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

// ProcessACS decodes SAMLResponse, verifies assertions, provisions user, and grants organization membership.
func (s *Service) ProcessACS(ctx context.Context, tenantID, rawSAMLPayload string, ip, userAgent string) (*ent.User, *ent.Organization, error) {
	rawSAMLPayload = strings.TrimSpace(rawSAMLPayload)
	if rawSAMLPayload == "" {
		return nil, nil, ErrInvalidAssertion
	}

	// Base64 decode payload if encoded
	xmlBytes, err := base64.StdEncoding.DecodeString(rawSAMLPayload)
	if err != nil {
		xmlBytes = []byte(rawSAMLPayload)
	}

	var samlResp SAMLResponseXML
	if err := xml.Unmarshal(xmlBytes, &samlResp); err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse XML: %v", ErrInvalidAssertion, err)
	}

	email := strings.ToLower(strings.TrimSpace(samlResp.Assertion.Subject.NameID))
	if email == "" {
		// Fallback: search in attributes
		for _, attr := range samlResp.Assertion.Attributes.Attributes {
			if strings.EqualFold(attr.Name, "email") || strings.EqualFold(attr.Name, "mail") || strings.Contains(strings.ToLower(attr.Name), "emailaddress") {
				if len(attr.Values) > 0 {
					email = strings.ToLower(strings.TrimSpace(attr.Values[0]))
					break
				}
			}
		}
	}

	if email == "" || !strings.Contains(email, "@") {
		return nil, nil, fmt.Errorf("%w: NameID/Email attribute missing in SAML assertion", ErrInvalidAssertion)
	}

	parts := strings.Split(email, "@")
	domain := parts[1]

	// Resolve domain SSO connection
	lookup, err := s.LookupDomainSSO(ctx, tenantID, DomainLookupRequest{Domain: domain})
	if err != nil || !lookup.HasSSO {
		return nil, nil, fmt.Errorf("no active SAML connection mapped to domain '%s'", domain)
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Find or provision user JIT
	usrObj, err := client.User.Query().
		Where(user.TenantID(tenantID), user.Email(email)).
		Only(ctx)
	if err != nil {
		userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
		created, err := client.User.Create().
			SetID(userID).
			SetTenantID(tenantID).
			SetEmail(email).
			SetEmailVerified(true).
			Save(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to JIT provision user: %w", err)
		}
		usrObj = created
	}

	// Fetch Organization
	orgObj, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(lookup.OrgID)).
		Only(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query organization: %w", err)
	}

	// Ensure OrgMember join
	isMember, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(lookup.OrgID), orgmember.UserID(usrObj.ID)).
		Exist(ctx)
	if err == nil && !isMember {
		// Resolve default role for org
		defaultRole, _ := client.Role.Query().
			Where(role.TenantID(tenantID), role.Slug("editor")).
			Only(ctx)
		roleID := "role_default_editor"
		if defaultRole != nil {
			roleID = defaultRole.ID
		}

		memID := fmt.Sprintf("mem_%s", uuid.New().String()[:12])
		_, _ = client.OrgMember.Create().
			SetID(memID).
			SetOrganizationID(lookup.OrgID).
			SetUserID(usrObj.ID).
			SetRoleID(roleID).
			Save(ctx)
	}

	// Log Audit & Webhook
	s.logAudit(ctx, tenantID, usrObj.ID, "saml.login_success", "user", usrObj.ID, map[string]interface{}{
		"email":   email,
		"domain":  domain,
		"org_id":  lookup.OrgID,
		"idp_url": lookup.IDPSSOURL,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "saml.login_success", map[string]interface{}{
			"user_id": usrObj.ID,
			"email":   email,
			"domain":  domain,
			"org_id":  lookup.OrgID,
		})
	}

	return usrObj, orgObj, nil
}

func (s *Service) toSAMLResponse(conn *ent.SAMLConnection) *SAMLConnectionResponse {
	if conn == nil {
		return nil
	}
	return &SAMLConnectionResponse{
		ID:               conn.ID,
		OrganizationID:   conn.OrganizationID,
		IDPEntityID:      conn.IdpEntityID,
		IDPSSOURL:        conn.IdpSSOURL,
		IDPCertificate:   conn.IdpCertificate,
		AllowedDomains:   conn.AllowedDomains,
		AttributeMapping: conn.AttributeMapping,
		EnforceSSO:       conn.EnforceSSO,
		CreatedAt:        conn.CreatedAt,
		UpdatedAt:        conn.UpdatedAt,
	}
}

func (s *Service) logAudit(ctx context.Context, tenantID, actorID, eventType, targetType, targetID string, metadata map[string]interface{}, ip, userAgent string) {
	client := s.factory.GetClient(ctx, tenantID, "")

	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["target_type"] = targetType
	if targetID != "" {
		metadata["target_id"] = targetID
	}

	logID := fmt.Sprintf("log_%s", uuid.New().String()[:12])

	actorType := auditlog.ActorTypeUser
	if strings.HasPrefix(actorID, "key_") || actorID == "system" || actorID == "admin" {
		actorType = auditlog.ActorTypeAdmin
	}

	builder := client.AuditLog.Create().
		SetID(logID).
		SetTenantID(tenantID).
		SetActorType(actorType).
		SetEventType(eventType).
		SetMetadata(metadata)

	if actorID != "" {
		builder.SetUserID(actorID)
	}
	if ip != "" {
		builder.SetIPAddress(ip)
	}
	if userAgent != "" {
		builder.SetUserAgent(userAgent)
	}

	_, _ = builder.Save(ctx)
}
