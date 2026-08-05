/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/saml_test.go
 * Tier: Automated Testing Layer / Unit & Integration Tests
 *
 * Description: Comprehensive test suite for Enterprise SAML 2.0 & Native SSO (FR-16).
 *              Verifies validation bounds, SAML connection CRUD, domain conflicts, domain lookups,
 *              ACS assertion processing, and JIT user provisioning.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

const sampleCert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL0b2+
-----END CERTIFICATE-----`

func setupTestSAMLService(t *testing.T) (*saml.Service, *clientfactory.ClientFactory, func()) {
	tmpDir, err := os.MkdirTemp("", "saml_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db") + "?_fk=1"
	factory, err := clientfactory.NewClientFactory("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to initialize client factory: %v", err)
	}

	ctx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(ctx, "tnt_test", "")

	// Seed Tenant & Organization
	_, err = client.Tenant.Create().SetID("tnt_test").SetName("Test Tenant").SetSlug("test-tenant").Save(ctx)
	if err != nil && !ent.IsConstraintError(err) {
		t.Fatalf("failed to seed tenant: %v", err)
	}

	_, err = client.Organization.Create().
		SetID("org_siemens").
		SetTenantID("tnt_test").
		SetName("Siemens AG").
		SetSlug("siemens").
		Save(ctx)
	if err != nil && !ent.IsConstraintError(err) {
		t.Fatalf("failed to seed organization: %v", err)
	}

	svc := saml.NewService(factory, nil)

	cleanup := func() {
		_ = factory.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return svc, factory, cleanup
}

func TestSAMLValidation(t *testing.T) {
	req := saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "ab", // Too short
		IDPSSOURL:      "https://idp.example.com/sso",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"siemens.com"},
	}
	if err := req.Validate(); err == nil {
		t.Errorf("expected error for short entity ID, got nil")
	}

	req = saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "http://www.okta.com/exk123",
		IDPSSOURL:      "not-a-url",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"siemens.com"},
	}
	if err := req.Validate(); err == nil {
		t.Errorf("expected error for invalid SSO URL, got nil")
	}

	req = saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "http://www.okta.com/exk123",
		IDPSSOURL:      "https://idp.example.com/sso",
		IDPCertificate: "invalid-cert-no-pem",
		AllowedDomains: []string{"siemens.com"},
	}
	if err := req.Validate(); err == nil {
		t.Errorf("expected error for non-PEM certificate, got nil")
	}

	req = saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "http://www.okta.com/exk123",
		IDPSSOURL:      "https://idp.example.com/sso",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"invalid_domain"},
	}
	if err := req.Validate(); err == nil {
		t.Errorf("expected error for invalid domain format, got nil")
	}

	req = saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "http://www.okta.com/exk123",
		IDPSSOURL:      "https://idp.example.com/sso",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"siemens.com", "siemens.de"},
		EnforceSSO:     true,
	}
	if err := req.Validate(); err != nil {
		t.Errorf("unexpected error for valid SAML request: %v", err)
	}
}

func TestSAMLConnectionLifecycle(t *testing.T) {
	svc, _, cleanup := setupTestSAMLService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	// 1. Create SAML Connection
	conn, err := svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "http://www.okta.com/exk123",
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"siemens.com", "siemens.de"},
		EnforceSSO:     true,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create SAML connection: %v", err)
	}
	if conn.ID == "" || !conn.EnforceSSO || len(conn.AllowedDomains) != 2 {
		t.Errorf("unexpected connection payload: %+v", conn)
	}

	// 2. Duplicate Org SAML Error
	_, err = svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "http://www.okta.com/exk999",
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"siemens.org"},
	}, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Errorf("expected duplicate SAML connection error, got nil")
	}

	// 3. Get SAML Connection
	fetched, err := svc.GetSAMLConnection(ctx, "tnt_test", "org_siemens")
	if err != nil {
		t.Fatalf("failed to get SAML connection: %v", err)
	}
	if fetched.IDPEntityID != "http://www.okta.com/exk123" {
		t.Errorf("unexpected entity ID: %s", fetched.IDPEntityID)
	}

	// 4. Domain Lookup Test
	lookup, err := svc.LookupDomainSSO(ctx, "tnt_test", saml.DomainLookupRequest{Domain: "siemens.com"})
	if err != nil {
		t.Fatalf("domain lookup failed: %v", err)
	}
	if !lookup.HasSSO || !lookup.EnforceSSO || lookup.OrgID != "org_siemens" {
		t.Errorf("unexpected domain lookup result: %+v", lookup)
	}

	// Unmapped domain
	unmappedLookup, err := svc.LookupDomainSSO(ctx, "tnt_test", saml.DomainLookupRequest{Domain: "gmail.com"})
	if err != nil {
		t.Fatalf("unmapped domain lookup failed: %v", err)
	}
	if unmappedLookup.HasSSO {
		t.Errorf("expected HasSSO false for gmail.com, got true")
	}

	// 5. Update SAML Connection
	enforce := false
	updated, err := svc.UpdateSAMLConnection(ctx, "tnt_test", "usr_admin", "org_siemens", saml.UpdateSAMLRequest{
		EnforceSSO: &enforce,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to update SAML connection: %v", err)
	}
	if updated.EnforceSSO {
		t.Errorf("expected enforce_sso false after update, got true")
	}

	// 6. Delete SAML Connection
	err = svc.DeleteSAMLConnection(ctx, "tnt_test", "usr_admin", "org_siemens", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to delete SAML connection: %v", err)
	}

	// Verify NotFound
	_, err = svc.GetSAMLConnection(ctx, "tnt_test", "org_siemens")
	if err == nil {
		t.Errorf("expected NotFound error after deletion, got nil")
	}
}

func TestProcessACS(t *testing.T) {
	svc, _, cleanup := setupTestSAMLService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	// Create SAML Connection for siemens.com
	_, err := svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    "http://www.okta.com/exk123",
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"siemens.com"},
		EnforceSSO:     true,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create SAML connection: %v", err)
	}

	// Mock XML SAMLResponse payload
	xmlPayload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="id123" IssueInstant="2026-08-05T12:00:00Z">
  <Issuer>http://www.okta.com/exk123</Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion123" IssueInstant="2026-08-05T12:00:00Z">
    <Issuer>http://www.okta.com/exk123</Issuer>
    <Subject>
      <NameID>alex@siemens.com</NameID>
    </Subject>
  </Assertion>
</Response>`)

	encodedXML := base64.StdEncoding.EncodeToString([]byte(xmlPayload))

	// Process ACS
	userObj, orgObj, err := svc.ProcessACS(ctx, "tnt_test", encodedXML, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to process ACS SAML assertion: %v", err)
	}

	if userObj.Email != "alex@siemens.com" || !userObj.EmailVerified {
		t.Errorf("unexpected user payload: %+v", userObj)
	}
	if orgObj.ID != "org_siemens" {
		t.Errorf("expected org_id 'org_siemens', got '%s'", orgObj.ID)
	}
}
