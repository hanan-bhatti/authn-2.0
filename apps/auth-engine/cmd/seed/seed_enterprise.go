/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/seed_enterprise.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: Demo organization and SAML connection seeder logic.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
)

// seedOrganization creates the demo organization, adds the administrator and
// the member account to it, and attaches a SAML connection so the enterprise
// single sign-on path has a configured tenant to exercise.
//
// Returns an error when the organization or a membership cannot be written.
func seedOrganization(ctx context.Context, client *ent.Client, users map[string]*ent.User) error {
	org, err := client.Organization.Query().Where(organization.ID(seedOrgID)).Only(ctx)
	if err != nil {
		org, err = client.Organization.Create().
			SetID(seedOrgID).
			SetTenantID(seedTenantID).
			SetName(seedOrgName).
			SetSlug(seedOrgSlug).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("seeding organization %s: %w", seedOrgID, err)
		}
	}

	memberships := []struct {
		membershipID string
		email        string
		roleID       string
	}{
		{"mem_00000000000000000000000000000001", "admin@authn.local", rbac.SystemRoleID(seedTenantID, "org_admin")},
		{"mem_00000000000000000000000000000002", "user.orgmember@authn.local", rbac.SystemRoleID(seedTenantID, "editor")},
	}

	for _, m := range memberships {
		u, ok := users[m.email]
		if !ok {
			return fmt.Errorf("organization member %s was not seeded", m.email)
		}

		exists, err := client.OrgMember.Query().
			Where(orgmember.OrganizationID(org.ID), orgmember.UserID(u.ID)).
			Exist(ctx)
		if err != nil {
			return fmt.Errorf("checking membership for %s: %w", m.email, err)
		}
		if exists {
			continue
		}

		if _, err := client.OrgMember.Create().
			SetID(m.membershipID).
			SetOrganizationID(org.ID).
			SetUserID(u.ID).
			SetRoleID(m.roleID).
			Save(ctx); err != nil {
			return fmt.Errorf("adding %s to organization: %w", m.email, err)
		}
	}

	return seedSAMLConnection(ctx, client, org.ID)
}

// seedSAMLConnection attaches a placeholder identity provider to the
// organization, unless one is already configured.
//
// The certificate and endpoints are not real. They exist so the SAML
// configuration screens and metadata endpoint have a record to render.
//
// Returns an error when the connection cannot be written.
func seedSAMLConnection(ctx context.Context, client *ent.Client, orgID string) error {
	configured, err := client.SAMLConnection.Query().
		Where(samlconnection.OrganizationID(orgID)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("checking existing SAML connection: %w", err)
	}
	if configured {
		return nil
	}

	if _, err := client.SAMLConnection.Create().
		SetID("saml_00000000000000000000000000000001").
		SetOrganizationID(orgID).
		SetIdpEntityID("https://idp.acme-corp.com/saml/metadata").
		SetIdpSSOURL("https://idp.acme-corp.com/saml/sso").
		SetIdpCertificate("-----BEGIN CERTIFICATE-----\nMIICXzCCAcegAwIBAgIU...\n-----END CERTIFICATE-----").
		SetAllowedDomains([]string{"acme-corp.com"}).
		SetEnforceSSO(true).
		Save(ctx); err != nil {
		return fmt.Errorf("seeding SAML connection: %w", err)
	}
	return nil
}
