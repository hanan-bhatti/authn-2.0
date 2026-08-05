/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/types.go
 * Tier: Business Logic Layer / DTOs & Validation
 *
 * Description: Data transfer objects, request/response models, validation rules,
 *              and limit bounds for Enterprise SAML 2.0 & Native SSO (FR-16).
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

// Validation Constants & Bounds
const (
	MinEntityIDLength      = 3
	MaxEntityIDLength      = 500
	MaxSSOURLLength        = 2048
	MaxCertLength          = 10000
	MaxAllowedDomains      = 20
	MinDomainLength        = 3
	MaxDomainLength        = 253
)

var (
	DomainRegex = regexp.MustCompile(`^(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Common Sentinel Errors
var (
	ErrSAMLNotFound       = errors.New("SAML connection configuration not found")
	ErrSAMLExists         = errors.New("SAML connection already exists for this organization")
	ErrInvalidEntityID    = fmt.Errorf("invalid IdP entity ID length (must be %d-%d chars)", MinEntityIDLength, MaxEntityIDLength)
	ErrInvalidSSOURL      = errors.New("invalid IdP SSO URL format (must be valid http/https URL)")
	ErrInvalidCert        = errors.New("invalid IdP certificate (must be valid PEM formatted X.509 certificate)")
	ErrInvalidDomains     = fmt.Errorf("allowed_domains must contain between 1 and %d valid domain names", MaxAllowedDomains)
	ErrDomainConflict     = errors.New("one or more domains are already mapped to another SAML connection in this tenant")
	ErrSSOEnforced        = errors.New("direct password and social authentication are disabled for this domain; corporate SSO is required")
	ErrInvalidAssertion   = errors.New("invalid, tampered, or expired SAML assertion XML")
	ErrSignatureFailed    = errors.New("SAML assertion signature verification failed using configured X.509 certificate")
	ErrAudienceMismatch   = errors.New("SAML assertion AudienceRestriction does not match expected Service Provider Entity ID")
	ErrAssertionExpired   = errors.New("SAML assertion timestamp has expired")
)

// CreateSAMLRequest represents payload to configure SAML for an organization.
type CreateSAMLRequest struct {
	OrganizationID   string            `json:"organization_id"`
	IDPEntityID      string            `json:"idp_entity_id"`
	IDPSSOURL        string            `json:"idp_sso_url"`
	IDPCertificate   string            `json:"idp_certificate"`
	AllowedDomains   []string          `json:"allowed_domains"`
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	EnforceSSO       bool              `json:"enforce_sso"`
}

// Validate checks constraints on CreateSAMLRequest.
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

	cleanedDomains := make([]string, 0, len(r.AllowedDomains))
	seen := make(map[string]bool)
	for _, d := range r.AllowedDomains {
		domain := strings.ToLower(strings.TrimSpace(d))
		if len(domain) < MinDomainLength || len(domain) > MaxDomainLength || !DomainRegex.MatchString(domain) {
			return fmt.Errorf("invalid domain format: %s", d)
		}
		if !seen[domain] {
			seen[domain] = true
			cleanedDomains = append(cleanedDomains, domain)
		}
	}
	r.AllowedDomains = cleanedDomains

	return nil
}

// UpdateSAMLRequest represents payload to update existing SAML settings.
type UpdateSAMLRequest struct {
	IDPEntityID      *string            `json:"idp_entity_id,omitempty"`
	IDPSSOURL        *string            `json:"idp_sso_url,omitempty"`
	IDPCertificate   *string            `json:"idp_certificate,omitempty"`
	AllowedDomains   []string           `json:"allowed_domains,omitempty"`
	AttributeMapping map[string]string  `json:"attribute_mapping,omitempty"`
	EnforceSSO       *bool              `json:"enforce_sso,omitempty"`
}

// Validate checks constraints on UpdateSAMLRequest.
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
		cleanedDomains := make([]string, 0, len(r.AllowedDomains))
		seen := make(map[string]bool)
		for _, d := range r.AllowedDomains {
			domain := strings.ToLower(strings.TrimSpace(d))
			if len(domain) < MinDomainLength || len(domain) > MaxDomainLength || !DomainRegex.MatchString(domain) {
				return fmt.Errorf("invalid domain format: %s", d)
			}
			if !seen[domain] {
				seen[domain] = true
				cleanedDomains = append(cleanedDomains, domain)
			}
		}
		r.AllowedDomains = cleanedDomains
	}

	return nil
}

// DomainLookupRequest represents request payload to check if an email domain requires SAML SSO.
type DomainLookupRequest struct {
	Email  string `json:"email,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// Validate checks constraints on DomainLookupRequest.
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

// DomainLookupResponse represents response payload for domain SSO detection.
type DomainLookupResponse struct {
	HasSSO     bool   `json:"has_sso"`
	EnforceSSO bool   `json:"enforce_sso"`
	OrgID      string `json:"org_id,omitempty"`
	OrgName    string `json:"org_name,omitempty"`
	IDPSSOURL  string `json:"idp_sso_url,omitempty"`
}

// ACSRequest represents Assertion Consumer Service payload received from SAML IdP POST.
type ACSRequest struct {
	SAMLResponse string `json:"SAMLResponse" form:"SAMLResponse"`
	RelayState   string `json:"RelayState,omitempty" form:"RelayState,omitempty"`
}

// SAMLConnectionResponse represents serialized SAMLConnection payload.
type SAMLConnectionResponse struct {
	ID               string            `json:"id"`
	OrganizationID   string            `json:"organization_id"`
	IDPEntityID      string            `json:"idp_entity_id"`
	IDPSSOURL        string            `json:"idp_sso_url"`
	IDPCertificate   string            `json:"idp_certificate"`
	AllowedDomains   []string          `json:"allowed_domains"`
	AttributeMapping map[string]string `json:"attribute_mapping,omitempty"`
	EnforceSSO       bool              `json:"enforce_sso"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}
