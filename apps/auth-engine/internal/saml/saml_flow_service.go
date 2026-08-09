/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/saml_flow_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: SAML AuthnRequest construction, response validation, and SSO user JIT provisioning.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

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
