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
	"encoding/xml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
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
	//
	// environment is the environment the event originated in, and decides which
	// of the tenant's endpoints receive it.
	Dispatch(tenantID, environment, eventType string, data map[string]interface{})
}

// Service carries out SAML connection management and assertion processing.
type Service struct {
	// factory yields tenant- and environment-scoped database clients.
	factory *clientfactory.ClientFactory
	// dispatcher emits lifecycle webhooks; nil disables them.
	dispatcher WebhookDispatcher
	// cfg supplies the deployment's public address, from which the published ACS
	// URL is derived, and the key SSO access tokens are signed with.
	cfg *config.Config
	// replay remembers consumed assertion IDs so a captured assertion cannot be
	// presented a second time inside its validity window.
	replay *assertionReplayGuard
	// sessions issues the session a validated assertion is carried by. It is the
	// same store the password, passkey and social paths write to, so an SSO
	// sign-in appears in the user's session list and is reachable by revocation.
	sessions *session.Repository
}

// NewService constructs a Service.
//
// sessions is required rather than optional, for the same reason it is on the
// social path: an assertion that authenticates a user but issues no session
// leaves them holding nothing they can present to the application, which is
// indistinguishable from a failed sign-in from the user's side.
//
// cfg is required for two reasons. It carries the deployment's public address,
// without which the ACS location published in service-provider metadata points at
// a local development host no real identity provider can reach. It also carries
// the key SSO access tokens are signed with, and the handler reads it to build the
// refresh cookie — so a Service without one completes a sign-in that nothing
// downstream accepts.
func NewService(factory *clientfactory.ClientFactory, dispatcher WebhookDispatcher, sessions *session.Repository, cfg *config.Config) *Service {
	return &Service{
		factory:    factory,
		dispatcher: dispatcher,
		replay:     newAssertionReplayGuard(),
		sessions:   sessions,
		cfg:        cfg,
	}
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
		Environment:      string(conn.Environment),
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
		SetID(idgen.New("log")).
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
	return idgen.New(prefix)
}
