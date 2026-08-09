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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	dsig "github.com/russellhaering/goxmldsig"
)

const sampleCert = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL0b2+
-----END CERTIFICATE-----`

// testAppBaseURL stands in for a real deployment address so the metadata
// assertions below fail if the published ACS URL ever reverts to a value baked
// into the source rather than derived from configuration.
const testSPEntityIDPrefix = "https://sp.test.example/saml/sp/"

const testAppBaseURL = "https://auth.acme-corp.example"

func testConfig() *config.Config {
	return &config.Config{
		AppBaseURL:                testAppBaseURL,
		SAMLAssertionConsumerPath: "/v1/saml/acs",
		SAMLSPEntityIDPrefix:      testSPEntityIDPrefix,
	}
}

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

	svc := saml.NewService(factory, nil, testConfig())

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

// signingIdentity is a throwaway RSA key and self-signed certificate standing in
// for an identity provider's signing material.
type signingIdentity struct {
	key     *rsa.PrivateKey
	cert    *x509.Certificate
	certPEM string
}

// newSigningIdentity mints an identity provider's signing material for one test.
func newSigningIdentity(t *testing.T) *signingIdentity {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return &signingIdentity{
		key:     key,
		cert:    cert,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

// sign returns responseXML with an enveloped XML-DSig signature over its
// Assertion element, produced with this identity's key.
func (s *signingIdentity) sign(t *testing.T, responseXML string) string {
	t.Helper()

	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		t.Fatalf("parse response for signing: %v", err)
	}

	assertion := doc.Root().FindElement("./Assertion")
	if assertion == nil {
		t.Fatal("response carries no Assertion to sign")
	}

	keyStore := dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{s.cert.Raw},
		PrivateKey:  s.key,
	})
	signingCtx := dsig.NewDefaultSigningContext(keyStore)
	if err := signingCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}

	signed, err := signingCtx.SignEnveloped(assertion)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	doc.Root().RemoveChild(assertion)
	doc.Root().AddChild(signed)

	out, err := doc.WriteToString()
	if err != nil {
		t.Fatalf("serialize signed response: %v", err)
	}
	return out
}

// acsResponseOptions describes the SAML response an individual case posts.
type acsResponseOptions struct {
	issuer       string
	nameID       string
	status       string
	notBefore    time.Time
	notOnOrAfter time.Time
	assertionID  string
}

// buildACSResponse renders a SAML response with the given properties, filling in
// values that a case did not care about.
func buildACSResponse(opts acsResponseOptions) string {
	if opts.issuer == "" {
		opts.issuer = testIdPEntityID
	}
	if opts.nameID == "" {
		opts.nameID = "alex@siemens.com"
	}
	if opts.status == "" {
		opts.status = "urn:oasis:names:tc:SAML:2.0:status:Success"
	}
	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-5 * time.Minute)
	}
	if opts.notOnOrAfter.IsZero() {
		opts.notOnOrAfter = time.Now().Add(5 * time.Minute)
	}
	if opts.assertionID == "" {
		opts.assertionID = fmt.Sprintf("assertion-%d", time.Now().UnixNano())
	}

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="response-1" IssueInstant="%s">
  <Issuer>%s</Issuer>
  <Status><StatusCode Value="%s"/></Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s">
    <Issuer>%s</Issuer>
    <Subject><NameID>%s</NameID></Subject>
    <Conditions NotBefore="%s" NotOnOrAfter="%s"/>
  </Assertion>
</Response>`,
		time.Now().UTC().Format(time.RFC3339),
		opts.issuer,
		opts.status,
		opts.assertionID,
		time.Now().UTC().Format(time.RFC3339),
		opts.issuer,
		opts.nameID,
		opts.notBefore.UTC().Format(time.RFC3339),
		opts.notOnOrAfter.UTC().Format(time.RFC3339),
	)
}

const testIdPEntityID = "http://www.okta.com/exk123"

// newACSFixture provisions a service with one active SAML connection trusting
// idp's certificate for the siemens.com domain.
func newACSFixture(t *testing.T, idp *signingIdentity) (*saml.Service, context.Context, func()) {
	t.Helper()

	svc, _, cleanup := setupTestSAMLService(t)
	ctx := privacy.NewBypassContext(context.Background())

	_, err := svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    testIdPEntityID,
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: idp.certPEM,
		AllowedDomains: []string{"siemens.com"},
		EnforceSSO:     true,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		cleanup()
		t.Fatalf("failed to create SAML connection: %v", err)
	}

	return svc, ctx, cleanup
}

// A correctly signed assertion authenticates its subject and provisions them
// into the organization the connection belongs to.
func TestProcessACSAcceptsSignedAssertion(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, cleanup := newACSFixture(t, idp)
	defer cleanup()

	payload := base64.StdEncoding.EncodeToString(
		[]byte(idp.sign(t, buildACSResponse(acsResponseOptions{}))))

	userObj, orgObj, err := svc.ProcessACS(ctx, "tnt_test", payload, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a correctly signed assertion must be accepted, got: %v", err)
	}
	if userObj.Email != "alex@siemens.com" || !userObj.EmailVerified {
		t.Errorf("unexpected user payload: %+v", userObj)
	}
	if orgObj.ID != "org_siemens" {
		t.Errorf("expected org_siemens, got %q", orgObj.ID)
	}
}

// Every one of these was accepted before assertion verification existed: the
// endpoint is unauthenticated, so each represents a pre-authentication account
// takeover for any tenant with SSO configured.
func TestProcessACSRejectsUnverifiableAssertions(t *testing.T) {
	cases := []struct {
		name string
		// build returns the raw response XML and whether to sign it with the
		// connection's trusted key.
		build func(t *testing.T, idp *signingIdentity) string
	}{
		{
			name: "unsigned assertion",
			build: func(t *testing.T, idp *signingIdentity) string {
				return buildACSResponse(acsResponseOptions{})
			},
		},
		{
			name: "signed by an untrusted key",
			build: func(t *testing.T, idp *signingIdentity) string {
				attacker := newSigningIdentity(t)
				return attacker.sign(t, buildACSResponse(acsResponseOptions{}))
			},
		},
		{
			name: "tampered after signing",
			build: func(t *testing.T, idp *signingIdentity) string {
				signed := idp.sign(t, buildACSResponse(acsResponseOptions{}))
				return strings.Replace(signed, "alex@siemens.com", "ceo@siemens.com", 1)
			},
		},
		{
			name: "expired validity window",
			build: func(t *testing.T, idp *signingIdentity) string {
				return idp.sign(t, buildACSResponse(acsResponseOptions{
					notBefore:    time.Now().Add(-2 * time.Hour),
					notOnOrAfter: time.Now().Add(-1 * time.Hour),
				}))
			},
		},
		{
			name: "not yet valid",
			build: func(t *testing.T, idp *signingIdentity) string {
				return idp.sign(t, buildACSResponse(acsResponseOptions{
					notBefore:    time.Now().Add(1 * time.Hour),
					notOnOrAfter: time.Now().Add(2 * time.Hour),
				}))
			},
		},
		{
			name: "unsuccessful status",
			build: func(t *testing.T, idp *signingIdentity) string {
				return idp.sign(t, buildACSResponse(acsResponseOptions{
					status: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
				}))
			},
		},
		{
			name: "issuer does not match the connection",
			build: func(t *testing.T, idp *signingIdentity) string {
				return idp.sign(t, buildACSResponse(acsResponseOptions{
					issuer: "http://attacker.example/idp",
				}))
			},
		},
		{
			name: "subject outside the connection's allowed domains",
			build: func(t *testing.T, idp *signingIdentity) string {
				return idp.sign(t, buildACSResponse(acsResponseOptions{
					nameID: "victim@other-company.com",
				}))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newSigningIdentity(t)
			svc, ctx, cleanup := newACSFixture(t, idp)
			defer cleanup()

			payload := base64.StdEncoding.EncodeToString([]byte(tc.build(t, idp)))

			userObj, _, err := svc.ProcessACS(ctx, "tnt_test", payload, "127.0.0.1", "TestAgent")
			if err == nil {
				t.Fatalf("assertion was accepted but must be rejected; it authenticated %v", userObj)
			}
			if userObj != nil {
				t.Errorf("a rejected assertion must not yield a user, got %+v", userObj)
			}
		})
	}
}

// An assertion is single-use: replaying a captured one inside its validity
// window must not re-authenticate the subject.
func TestProcessACSRejectsReplayedAssertion(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, cleanup := newACSFixture(t, idp)
	defer cleanup()

	payload := base64.StdEncoding.EncodeToString(
		[]byte(idp.sign(t, buildACSResponse(acsResponseOptions{assertionID: "assertion-replay-1"}))))

	if _, _, err := svc.ProcessACS(ctx, "tnt_test", payload, "127.0.0.1", "TestAgent"); err != nil {
		t.Fatalf("first presentation must succeed, got: %v", err)
	}
	if _, _, err := svc.ProcessACS(ctx, "tnt_test", payload, "127.0.0.1", "TestAgent"); err == nil {
		t.Fatal("replaying the same assertion must be rejected")
	}
}

func TestGetSPMetadataHandler(t *testing.T) {
	svc, factory, cleanup := setupTestSAMLService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(ctx, "tnt_test", "")
	_, _ = client.Organization.Create().SetID("org_test").SetTenantID("tnt_test").SetName("Test Org").SetSlug("test-org").Save(ctx)

	// Create SAML Connection for org_test
	_, err := svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_test",
		IDPEntityID:    "http://www.okta.com/exk999",
		IDPSSOURL:      "https://test.okta.com/app/sso/saml",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"test.com"},
		EnforceSSO:     true,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create SAML connection: %v", err)
	}

	handler := saml.NewHandler(svc)
	app := fiber.New()
	handler.RegisterRoutes(app, nil, nil)

	// 1. Successful SP Metadata Fetch
	req := httptest.NewRequest("GET", "/v1/saml/metadata/org_test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed executing SP metadata request: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got '%s'", contentType)
	}
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "public, max-age=3600" {
		t.Errorf("expected Cache-Control public, max-age=3600, got '%s'", cacheControl)
	}

	// The ACS location an IdP posts assertions to must come from configuration.
	// A hardcoded address here reaches every identity provider that consumes
	// this document and points them all at the wrong host.
	metadataBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed reading SP metadata body: %v", err)
	}
	wantACS := testAppBaseURL + "/v1/saml/acs"
	if !strings.Contains(string(metadataBody), `Location="`+wantACS+`"`) {
		t.Errorf("SP metadata does not advertise the configured ACS URL %q; body: %s", wantACS, metadataBody)
	}
	if strings.Contains(string(metadataBody), "localhost") {
		t.Errorf("SP metadata advertises a localhost address; body: %s", metadataBody)
	}

	// 2. Non-existent Organization Metadata Fetch (404 Guard)
	req404 := httptest.NewRequest("GET", "/v1/saml/metadata/nonexistent_org", nil)
	resp404, _ := app.Test(req404)
	if resp404.StatusCode != 404 {
		t.Errorf("expected status 404 for nonexistent org, got %d", resp404.StatusCode)
	}

	// 3. Non-GET Verb Enforcement
	reqPost := httptest.NewRequest("POST", "/v1/saml/metadata/org_test", nil)
	respPost, _ := app.Test(reqPost)
	if respPost.StatusCode != 405 {
		t.Errorf("expected status 405 for POST, got %d", respPost.StatusCode)
	}
}

// The entity ID published in metadata and the one an assertion's audience is
// checked against must be the same string. If they diverge, every IdP that sets
// an AudienceRestriction — which is most of them — has its assertions rejected
// with no indication why.
func TestSPEntityIDIsConsistentAcrossMetadataAndAudience(t *testing.T) {
	svc, _, cleanup := setupTestSAMLService(t)
	defer cleanup()

	const orgID = "org_consistency"
	got := saml.SPEntityIDForTest(svc, orgID)

	// Built independently from the configured prefix, so this fails if the
	// accessor stops honouring configuration.
	want := testSPEntityIDPrefix + orgID
	if got != want {
		t.Errorf("SP entity ID = %q, want %q (must derive from SAML_SP_ENTITY_ID_PREFIX)", got, want)
	}
	// checkAudience compares against exactly this value, so an assertion naming
	// it must pass and one naming anything else must not.
	if err := saml.CheckAudienceForTest(want, got); err != nil {
		t.Errorf("an assertion addressed to the published entity ID must be accepted: %v", err)
	}
	if err := saml.CheckAudienceForTest("https://elsewhere.example/sp/"+orgID, got); err == nil {
		t.Error("an assertion addressed to a different service provider must be rejected")
	}
}
