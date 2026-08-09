/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/types.go
 * Tier: Business Logic Layer / DTOs & Validation
 *
 * Description: Request and response payloads for Enterprise SAML 2.0 SSO
 *              (FR-16), the bounds every caller-supplied field is checked
 *              against, and the sentinel errors the service layer returns.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Bounds on caller-supplied SAML configuration. Every field arriving from an
// API request is length-checked before it reaches storage, so a client cannot
// use a connection record as unbounded storage or push an oversized value into
// the metadata document.
const (
	// MinEntityIDLength is the shortest accepted identity-provider entity ID.
	MinEntityIDLength = 3
	// MaxEntityIDLength is the longest accepted identity-provider entity ID.
	MaxEntityIDLength = 500
	// MaxSSOURLLength is the longest accepted identity-provider SSO URL.
	MaxSSOURLLength = 2048
	// MaxCertLength is the longest accepted PEM certificate blob.
	MaxCertLength = 10000
	// MaxAllowedDomains caps how many email domains one connection may claim.
	MaxAllowedDomains = 20
	// MinDomainLength is the shortest plausible domain, as in "a.b".
	MinDomainLength = 3
	// MaxDomainLength is the longest legal DNS name.
	MaxDomainLength = 253
)

// DomainRegex matches a DNS hostname of two or more labels. Each label is
// alphanumeric with interior hyphens and at most 63 characters. A single-label
// value is rejected: an email domain always has a public suffix.
var DomainRegex = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Sentinel errors returned by the SAML service. Handlers match on these with
// errors.Is to choose a status code, so each maps to exactly one HTTP outcome.
var (
	// ErrSAMLNotFound reports that the organization has no SAML connection.
	ErrSAMLNotFound = errors.New("SAML connection configuration not found")
	// ErrSAMLExists reports that the organization already has a connection.
	ErrSAMLExists = errors.New("SAML connection already exists for this organization")
	// ErrInvalidEntityID reports an entity ID outside the accepted length range.
	ErrInvalidEntityID = fmt.Errorf("invalid IdP entity ID length (must be %d-%d chars)", MinEntityIDLength, MaxEntityIDLength)
	// ErrInvalidSSOURL reports an SSO URL that is not a well-formed http(s) URL.
	ErrInvalidSSOURL = errors.New("invalid IdP SSO URL format (must be valid http/https URL)")
	// ErrInvalidCert reports a certificate that is not a PEM X.509 blob.
	ErrInvalidCert = errors.New("invalid IdP certificate (must be valid PEM formatted X.509 certificate)")
	// ErrInvalidDomains reports a domain list that is empty, oversized, or
	// contains a malformed name.
	ErrInvalidDomains = fmt.Errorf("allowed_domains must contain between 1 and %d valid domain names", MaxAllowedDomains)
	// ErrDomainConflict reports a domain already claimed by another connection
	// in the same tenant.
	ErrDomainConflict = errors.New("one or more domains are already mapped to another SAML connection in this tenant")
	// ErrSSOEnforced reports that a domain requires corporate SSO, so password
	// and social sign-in must be refused for it. It is returned by the
	// authentication paths that consult EnforceSSO, not by this package.
	ErrSSOEnforced = errors.New("direct password and social authentication are disabled for this domain; corporate SSO is required")
	// ErrInvalidAssertion reports an assertion that cannot be parsed or carries
	// no usable subject.
	ErrInvalidAssertion = errors.New("invalid, tampered, or expired SAML assertion XML")
	// ErrSignatureFailed reports an assertion whose XML signature does not
	// verify against the connection's configured certificate.
	//
	// Nothing returns this yet: ProcessACS does not verify assertion
	// signatures. See the package notes on the ACS endpoint.
	ErrSignatureFailed = errors.New("SAML assertion signature verification failed using configured X.509 certificate")
	// ErrAudienceMismatch reports an assertion whose AudienceRestriction names
	// a different service provider. Not yet returned — ProcessACS does not
	// check the audience.
	ErrAudienceMismatch = errors.New("SAML assertion AudienceRestriction does not match expected Service Provider Entity ID")
	// ErrAssertionExpired reports an assertion outside its Conditions validity
	// window. Not yet returned — ProcessACS does not check the window.
	ErrAssertionExpired = errors.New("SAML assertion timestamp has expired")
)

// CreateSAMLRequest configures SAML SSO for an organization.
type CreateSAMLRequest struct {
	// OrganizationID is the organization to configure. The handler overwrites
	// this from the URL path, so a body value cannot redirect the write.
	OrganizationID string `json:"organization_id"`
	// IDPEntityID is the identity provider's unique identifier.
	IDPEntityID string `json:"idp_entity_id"`
	// IDPSSOURL is where users are sent to authenticate.
	IDPSSOURL string `json:"idp_sso_url"`
	// IDPCertificate is the provider's PEM X.509 signing certificate.
	IDPCertificate string `json:"idp_certificate"`
	// AllowedDomains lists the email domains routed to this provider. Each may
	// be claimed by only one connection per tenant.
	AllowedDomains []string `json:"allowed_domains"`
	// AttributeMapping maps provider attribute names onto engine fields.
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	// EnforceSSO makes SSO the only way to sign in from these domains.
	EnforceSSO bool `json:"enforce_sso"`
}

// Validate checks and normalizes the request in place, lowercasing domains and
// removing duplicates so stored values compare consistently.
//
// Returns a sentinel error for each bound it enforces, or a descriptive error
// naming a malformed domain.
func (r *CreateSAMLRequest) Validate() error {
	r.OrganizationID = strings.TrimSpace(r.OrganizationID)
	if r.OrganizationID == "" {
		return errors.New("organization_id is required")
	}

	r.IDPEntityID = strings.TrimSpace(r.IDPEntityID)
	if len(r.IDPEntityID) < MinEntityIDLength || len(r.IDPEntityID) > MaxEntityIDLength {
		return ErrInvalidEntityID
	}

	r.IDPSSOURL = strings.TrimSpace(r.IDPSSOURL)
	if len(r.IDPSSOURL) > MaxSSOURLLength {
		return ErrInvalidSSOURL
	}
	u, err := url.ParseRequestURI(r.IDPSSOURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ErrInvalidSSOURL
	}

	r.IDPCertificate = strings.TrimSpace(r.IDPCertificate)
	if r.IDPCertificate == "" || len(r.IDPCertificate) > MaxCertLength {
		return ErrInvalidCert
	}
	if !strings.Contains(r.IDPCertificate, "CERTIFICATE") {
		return ErrInvalidCert
	}

	if len(r.AllowedDomains) == 0 || len(r.AllowedDomains) > MaxAllowedDomains {
		return ErrInvalidDomains
	}

	cleanedDomains, err := normalizeDomains(r.AllowedDomains)
	if err != nil {
		return err
	}
	r.AllowedDomains = cleanedDomains

	return nil
}

// UpdateSAMLRequest changes an existing connection. A nil pointer or nil slice
// leaves that field untouched, which is what separates "not supplied" from
// "set to empty".
type UpdateSAMLRequest struct {
	// IDPEntityID replaces the provider's identifier when non-nil.
	IDPEntityID *string `json:"idp_entity_id,omitempty"`
	// IDPSSOURL replaces the sign-in URL when non-nil.
	IDPSSOURL *string `json:"idp_sso_url,omitempty"`
	// IDPCertificate replaces the signing certificate when non-nil.
	IDPCertificate *string `json:"idp_certificate,omitempty"`
	// AllowedDomains replaces the whole domain list when non-nil.
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	// AttributeMapping replaces the attribute mapping when non-nil.
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	// EnforceSSO replaces the enforcement flag when non-nil.
	EnforceSSO *bool `json:"enforce_sso,omitempty"`
}

// Validate checks and normalizes the supplied fields in place, ignoring those
// left nil.
//
// Returns the same sentinel errors as CreateSAMLRequest.Validate.
func (r *UpdateSAMLRequest) Validate() error {
	if r.IDPEntityID != nil {
		id := strings.TrimSpace(*r.IDPEntityID)
		if len(id) < MinEntityIDLength || len(id) > MaxEntityIDLength {
			return ErrInvalidEntityID
		}
		*r.IDPEntityID = id
	}

	if r.IDPSSOURL != nil {
		sso := strings.TrimSpace(*r.IDPSSOURL)
		if len(sso) > MaxSSOURLLength {
			return ErrInvalidSSOURL
		}
		u, err := url.ParseRequestURI(sso)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return ErrInvalidSSOURL
		}
		*r.IDPSSOURL = sso
	}

	if r.IDPCertificate != nil {
		cert := strings.TrimSpace(*r.IDPCertificate)
		if cert == "" || len(cert) > MaxCertLength || !strings.Contains(cert, "CERTIFICATE") {
			return ErrInvalidCert
		}
		*r.IDPCertificate = cert
	}

	if r.AllowedDomains != nil {
		if len(r.AllowedDomains) == 0 || len(r.AllowedDomains) > MaxAllowedDomains {
			return ErrInvalidDomains
		}
		cleanedDomains, err := normalizeDomains(r.AllowedDomains)
		if err != nil {
			return err
		}
		r.AllowedDomains = cleanedDomains
	}

	return nil
}

// normalizeDomains lowercases and trims each domain, rejects any that is
// malformed or out of bounds, and drops duplicates while preserving order.
//
// Returns an error naming the first offending value.
func normalizeDomains(domains []string) ([]string, error) {
	cleaned := make([]string, 0, len(domains))
	seen := make(map[string]bool)
	for _, d := range domains {
		domain := strings.ToLower(strings.TrimSpace(d))
		if len(domain) < MinDomainLength || len(domain) > MaxDomainLength || !DomainRegex.MatchString(domain) {
			return nil, fmt.Errorf("invalid domain format: %s", d)
		}
		if !seen[domain] {
			seen[domain] = true
			cleaned = append(cleaned, domain)
		}
	}
	return cleaned, nil
}

// DomainLookupRequest asks whether an email address must sign in through SSO.
type DomainLookupRequest struct {
	// Email is the address to derive the domain from when Domain is absent.
	Email string `json:"email,omitempty"`
	// Domain is the domain to look up directly.
	Domain string `json:"domain,omitempty"`
}

// Validate normalizes the request in place, deriving Domain from Email when
// only an address was supplied.
//
// Returns an error when neither field yields a usable domain.
func (r *DomainLookupRequest) Validate() error {
	r.Email = strings.TrimSpace(strings.ToLower(r.Email))
	r.Domain = strings.TrimSpace(strings.ToLower(r.Domain))

	if r.Domain == "" && r.Email != "" {
		if addr, err := mail.ParseAddress(r.Email); err == nil {
			parts := strings.Split(addr.Address, "@")
			if len(parts) == 2 {
				r.Domain = parts[1]
			}
		}
	}

	if r.Domain == "" {
		return errors.New("email or valid domain is required")
	}

	return nil
}

// DomainLookupResponse reports how a domain must authenticate.
type DomainLookupResponse struct {
	// HasSSO reports whether any connection claims the domain.
	HasSSO bool `json:"has_sso"`
	// EnforceSSO reports whether SSO is the only permitted method.
	EnforceSSO bool `json:"enforce_sso"`
	// OrgID is the organization the domain maps to.
	OrgID string `json:"org_id,omitempty"`
	// OrgName is that organization's display name.
	OrgName string `json:"org_name,omitempty"`
	// IDPSSOURL is where the caller should send the user to authenticate.
	IDPSSOURL string `json:"idp_sso_url,omitempty"`
}

// ACSRequest is the payload an identity provider posts to the Assertion
// Consumer Service. Both bindings are accepted: JSON, and the form encoding a
// real provider uses under the HTTP-POST binding.
type ACSRequest struct {
	// SAMLResponse is the base64-encoded SAML response document.
	SAMLResponse string `json:"SAMLResponse" form:"SAMLResponse"`
	// RelayState is the opaque value echoed back from the authentication
	// request, used to resume where the user left off.
	RelayState string `json:"RelayState,omitempty" form:"RelayState,omitempty"`
}

// SAMLConnectionResponse is the API representation of a stored connection.
type SAMLConnectionResponse struct {
	// ID is the connection's identifier.
	ID string `json:"id"`
	// OrganizationID is the organization it belongs to.
	OrganizationID string `json:"organization_id"`
	// IDPEntityID is the identity provider's identifier.
	IDPEntityID string `json:"idp_entity_id"`
	// IDPSSOURL is where users authenticate.
	IDPSSOURL string `json:"idp_sso_url"`
	// IDPCertificate is the provider's public signing certificate. It is public
	// key material, so returning it discloses nothing secret.
	IDPCertificate string `json:"idp_certificate"`
	// AllowedDomains lists the email domains routed to this provider.
	AllowedDomains []string `json:"allowed_domains"`
	// AttributeMapping maps provider attributes onto engine fields.
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	// EnforceSSO reports whether SSO is mandatory for these domains.
	EnforceSSO bool `json:"enforce_sso"`
	// CreatedAt is when the connection was configured.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when it last changed.
	UpdatedAt time.Time `json:"updated_at"`
}
