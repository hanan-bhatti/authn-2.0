/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Business logic for Enterprise SAML 2.0 SSO (FR-16) — connection
 *              CRUD with tenant-wide domain-exclusivity enforcement, email
 *              domain to identity-provider resolution, assertion consumption
 *              with just-in-time user provisioning and organization membership,
 *              plus audit and webhook emission for each of those.
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
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

const (
	// fallbackAppBaseURL and fallbackAssertionConsumerPath reproduce the
	// defaults config.Load applies to APP_BASE_URL and SAML_ACS_PATH. They are
	// used only when the service is constructed without a Config, which leaves
	// the published ACS location pointing at a local development address.
	fallbackAppBaseURL            = "http://localhost:8080"
	fallbackAssertionConsumerPath = "/v1/saml/acs"

	// fallbackSPEntityIDPrefix mirrors the SAML_SP_ENTITY_ID_PREFIX default and
	// applies only when the service is built without a Config.
	fallbackSPEntityIDPrefix = "https://authn.com/saml/sp/"

	// defaultMemberRoleSlug is the role new SSO users are granted in the
	// organization their email domain maps to.
	defaultMemberRoleSlug = "editor"

	// defaultMemberRoleID is used when the tenant has no role matching
	// defaultMemberRoleSlug, so membership is still recorded rather than lost.
	defaultMemberRoleID = "role_default_editor"

	// idSuffixLength is how much of a generated UUID is kept in a record ID.
	idSuffixLength = 12
)

// WebhookDispatcher delivers SAML lifecycle events to a tenant's subscribers.
type WebhookDispatcher interface {
	// Dispatch queues an event for delivery. Implementations must not block.
	Dispatch(tenantID, eventType string, data map[string]interface{})
}

// Service carries out SAML connection management and assertion processing.
type Service struct {
	// factory yields tenant- and environment-scoped database clients.
	factory *clientfactory.ClientFactory
	// dispatcher emits lifecycle webhooks; nil disables them.
	dispatcher WebhookDispatcher
	// cfg supplies the deployment's public address, from which the published
	// ACS URL is derived. It may be nil, in which case the fallback constants apply.
	cfg *config.Config
	// replay remembers consumed assertion IDs so a captured assertion cannot be
	// presented a second time inside its validity window.
	replay *assertionReplayGuard
}

// NewService constructs a Service.
//
// cfg is optional in signature only. Without it the service cannot know the
// deployment's public address and falls back to the local development default,
// which makes the ACS location published in service-provider metadata unusable
// by a real identity provider. Production callers must pass it.
func NewService(factory *clientfactory.ClientFactory, dispatcher WebhookDispatcher, cfg ...*config.Config) *Service {
	s := &Service{
		factory:    factory,
		dispatcher: dispatcher,
		replay:     newAssertionReplayGuard(),
	}
	if len(cfg) > 0 {
		s.cfg = cfg[0]
	}
	return s
}

// spEntityID returns the service-provider entity ID for an organization, which
// is published in metadata and checked against an assertion's audience.
func (s *Service) spEntityID(organizationID string) string {
	if s.cfg != nil && s.cfg.SAMLSPEntityIDPrefix != "" {
		return s.cfg.SAMLSPEntityID(organizationID)
	}
	return fallbackSPEntityIDPrefix + organizationID
}

// AssertionConsumerURL returns the absolute ACS endpoint to publish in
// service-provider metadata and register with each identity provider.
//
// It is derived from the configured public base URL so that a deployment which
// changes address updates one setting rather than every provider registration.
func (s *Service) AssertionConsumerURL() string {
	if s.cfg != nil {
		return s.cfg.SAMLAssertionConsumerURL()
	}
	return fallbackAppBaseURL + fallbackAssertionConsumerPath
}

// SAMLResponseXML is the subset of a SAML 2.0 Response the engine reads.
type SAMLResponseXML struct {
	// XMLName binds this struct to the Response element.
	XMLName xml.Name `xml:"Response"`
	// ID is the response's unique identifier.
	ID string `xml:"ID,attr"`
	// IssueInstant is when the identity provider produced the response.
	IssueInstant string `xml:"IssueInstant,attr"`
	// Destination is the ACS URL the response was addressed to.
	Destination string `xml:"Destination,attr"`
	// Issuer identifies the identity provider that produced the response.
	Issuer string `xml:"Issuer"`
	// Status carries the provider's success or failure code.
	Status SAMLStatus `xml:"Status"`
	// Assertion is the identity statement being conveyed.
	Assertion SAMLAssertion `xml:"Assertion"`
}

// SAMLStatus wraps the response status code.
type SAMLStatus struct {
	// StatusCode is the outcome the identity provider reports.
	StatusCode SAMLStatusCode `xml:"StatusCode"`
}

// SAMLStatusCode holds a SAML status URN.
type SAMLStatusCode struct {
	// Value is the status URN, success being
	// urn:oasis:names:tc:SAML:2.0:status:Success.
	Value string `xml:"Value,attr"`
}

// SAMLAssertion is the identity statement inside a response.
type SAMLAssertion struct {
	// ID is the assertion's unique identifier.
	ID string `xml:"ID,attr"`
	// IssueInstant is when the assertion was produced.
	IssueInstant string `xml:"IssueInstant,attr"`
	// Issuer identifies the asserting identity provider.
	Issuer string `xml:"Issuer"`
	// Subject names the authenticated principal.
	Subject SAMLSubject `xml:"Subject"`
	// Conditions carries the assertion's validity window.
	Conditions SAMLConditions `xml:"Conditions"`
	// Attributes carries additional claims such as email or display name.
	Attributes SAMLAttributeStatement `xml:"AttributeStatement"`
}

// SAMLSubject names the principal an assertion is about.
type SAMLSubject struct {
	// NameID is the principal identifier, an email address under the
	// emailAddress format this service provider advertises.
	NameID string `xml:"NameID"`
}

// SAMLConditions is the validity window an assertion is constrained to.
type SAMLConditions struct {
	// NotBefore is the instant the assertion becomes valid, RFC 3339.
	NotBefore string `xml:"NotBefore,attr"`
	// NotOnOrAfter is the instant the assertion stops being valid, RFC 3339.
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	// AudienceRestrictions names the service providers the assertion may be
	// presented to. An assertion carrying none is unrestricted.
	AudienceRestrictions []SAMLAudienceRestriction `xml:"AudienceRestriction"`
}

// SAMLAudienceRestriction limits an assertion to a set of service providers.
type SAMLAudienceRestriction struct {
	// Audiences holds the entity IDs the assertion is addressed to.
	Audiences []string `xml:"Audience"`
}

// SAMLAttributeStatement groups the attributes an assertion carries.
type SAMLAttributeStatement struct {
	// Attributes is the list of provider-supplied claims.
	Attributes []SAMLAttribute `xml:"Attribute"`
}

// SAMLAttribute is a single named claim.
type SAMLAttribute struct {
	// Name is the attribute name, which varies by identity provider.
	Name string `xml:"Name,attr"`
	// Values holds the attribute's values; the first is used.
	Values []string `xml:"AttributeValue"`
}

// subjectEmail returns the lowercased email address an assertion names, or ""
// when it carries none.
//
// The Subject NameID is preferred, since this service provider advertises the
// emailAddress format. Identity providers that put the address in an attribute
// instead are accommodated by scanning the common attribute names.
func subjectEmail(assertion SAMLAssertion) string {
	email := strings.ToLower(strings.TrimSpace(assertion.Subject.NameID))
	if email == "" {
		for _, attr := range assertion.Attributes.Attributes {
			name := strings.ToLower(attr.Name)
			if name == "email" || name == "mail" || strings.Contains(name, "emailaddress") {
				if len(attr.Values) > 0 {
					email = strings.ToLower(strings.TrimSpace(attr.Values[0]))
					break
				}
			}
		}
	}
	if !strings.Contains(email, "@") {
		return ""
	}
	return email
}

// connectionAllowsDomain reports whether conn is authorized to assert
// identities at the given email domain.
//
// A signature proves who issued an assertion, not which identities they may
// speak for. Without this check any configured provider could assert an address
// at another organization's domain and be provisioned into it.
func connectionAllowsDomain(conn *ent.SAMLConnection, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, allowed := range conn.AllowedDomains {
		if strings.EqualFold(strings.TrimSpace(allowed), domain) {
			return true
		}
	}
	return false
}

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

	samlID := newID("saml")

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

// ProcessACS consumes a SAML response posted to the Assertion Consumer Service
// and returns the authenticated user together with their organization.
//
// The subject's email is taken from NameID, falling back to a scan of the
// attribute statement because identity providers differ over which attribute
// name carries the address. Its domain selects the connection, and therefore
// the organization the user is provisioned into.
//
// A subject with no existing user is created on the spot with email_verified
// set, on the basis that the identity provider owns the domain and has already
// verified the address. Membership of the mapped organization is granted the
// same way, so a new hire reaches the right organization without an invitation.
//
// Returns ErrInvalidAssertion when the payload is unparseable or carries no
// usable email, an error when no connection claims the domain, or a wrapped
// storage error from provisioning.
func (s *Service) ProcessACS(ctx context.Context, tenantID, rawSAMLPayload string, ip, userAgent string) (*ent.User, *ent.Organization, error) {
	rawSAMLPayload = strings.TrimSpace(rawSAMLPayload)
	if rawSAMLPayload == "" {
		return nil, nil, ErrInvalidAssertion
	}

	// Identity providers send the response base64-encoded under the HTTP-POST
	// binding; a payload that does not decode is treated as raw XML.
	xmlBytes, err := base64.StdEncoding.DecodeString(rawSAMLPayload)
	if err != nil {
		xmlBytes = []byte(rawSAMLPayload)
	}

	doc, err := parseSAMLDocument(xmlBytes)
	if err != nil {
		return nil, nil, err
	}

	// The Issuer is read from unverified XML, so it serves purely as a lookup
	// key: it selects which certificate the signature is tested against and
	// grants nothing on its own. Every field used after this point is read from
	// bytes that certificate has proven.
	client := s.factory.GetClient(ctx, tenantID, "")
	conn, err := client.SAMLConnection.Query().
		Where(samlconnection.IdpEntityID(doc.issuer())).
		Only(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: no SAML connection matches the asserted issuer", ErrInvalidAssertion)
	}

	now := time.Now()
	verified, err := verifyAssertion(doc, conn, now, s.spEntityID(conn.OrganizationID))
	if err != nil {
		s.logAudit(ctx, tenantID, "", "saml.login_rejected", "saml_connection", conn.ID, map[string]interface{}{
			"idp_entity_id": conn.IdpEntityID,
			"reason":        err.Error(),
		}, ip, userAgent)
		return nil, nil, err
	}

	// An assertion is single-use. Without this, a captured assertion could be
	// replayed for the remainder of its validity window.
	if !s.replay.consume(tenantID+"|"+verified.assertion.ID, verified.expiresAt, now) {
		return nil, nil, fmt.Errorf("%w: assertion has already been used", ErrInvalidAssertion)
	}

	email := subjectEmail(verified.assertion)
	if email == "" {
		return nil, nil, fmt.Errorf("%w: NameID/Email attribute missing in SAML assertion", ErrInvalidAssertion)
	}

	// The subject's domain must be one this connection is authorized for, so a
	// provider cannot assert identities belonging to another organization.
	domain := email[strings.LastIndex(email, "@")+1:]
	if !connectionAllowsDomain(conn, domain) {
		return nil, nil, fmt.Errorf("%w: issuer is not authorized for domain %q", ErrInvalidAssertion, domain)
	}

	usrObj, err := client.User.Query().
		Where(user.TenantID(tenantID), user.Email(email)).
		Only(ctx)
	if err != nil {
		created, err := client.User.Create().
			SetID(newID("usr")).
			SetTenantID(tenantID).
			SetEmail(email).
			SetEmailVerified(true).
			Save(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to JIT provision user: %w", err)
		}
		usrObj = created
	}

	orgObj, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(conn.OrganizationID)).
		Only(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query organization: %w", err)
	}

	isMember, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(conn.OrganizationID), orgmember.UserID(usrObj.ID)).
		Exist(ctx)
	if err == nil && !isMember {
		defaultRole, _ := client.Role.Query().
			Where(role.TenantID(tenantID), role.Slug(defaultMemberRoleSlug)).
			Only(ctx)
		roleID := defaultMemberRoleID
		if defaultRole != nil {
			roleID = defaultRole.ID
		}

		// A failed membership write leaves the user signed in without org
		// access, which is recoverable by an administrator; it is not worth
		// failing an otherwise valid authentication over.
		_, _ = client.OrgMember.Create().
			SetID(newID("mem")).
			SetOrganizationID(conn.OrganizationID).
			SetUserID(usrObj.ID).
			SetRoleID(roleID).
			Save(ctx)
	}

	s.logAudit(ctx, tenantID, usrObj.ID, "saml.login_success", "user", usrObj.ID, map[string]interface{}{
		"email":   email,
		"domain":  domain,
		"org_id":  conn.OrganizationID,
		"idp_url": conn.IdpSSOURL,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "saml.login_success", map[string]interface{}{
			"user_id": usrObj.ID,
			"email":   email,
			"domain":  domain,
			"org_id":  conn.OrganizationID,
		})
	}

	return usrObj, orgObj, nil
}

// toSAMLResponse projects a stored connection onto its API representation,
// returning nil for a nil connection.
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

// logAudit records an audit entry for a SAML operation.
//
// Failures are swallowed: an unwritten audit row must not fail the operation
// the caller is midway through, and the error has nowhere useful to go from here.
func (s *Service) logAudit(ctx context.Context, tenantID, actorID, eventType, targetType, targetID string, metadata map[string]interface{}, ip, userAgent string) {
	client := s.factory.GetClient(ctx, tenantID, "")

	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["target_type"] = targetType
	if targetID != "" {
		metadata["target_id"] = targetID
	}

	actorType := auditlog.ActorTypeUser
	if strings.HasPrefix(actorID, "key_") || actorID == "system" || actorID == "admin" {
		actorType = auditlog.ActorTypeAdmin
	}

	builder := client.AuditLog.Create().
		SetID(newID("log")).
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

// newID returns a prefixed record identifier such as "saml_1a2b3c4d5e6f".
func newID(prefix string) string {
	return fmt.Sprintf("%s_%s", prefix, uuid.New().String()[:idSuffixLength])
}
