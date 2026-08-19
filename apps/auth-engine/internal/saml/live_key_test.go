/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/live_key_test.go
 * Tier: Automated Testing Layer / Unit Tests
 *
 * Description: Tests for the credential a live SAML connection takes to write —
 *              that a test-scoped caller can neither file one, edit one, promote
 *              a trial into one nor delete one, that its own test connection is
 *              unaffected, and that a live-scoped caller and a bypass are both
 *              free to do all of it.
 *
 * The connection is the one entity the privacy interceptor deliberately does not
 * narrow by environment, so nothing but this guard stands between a test key and
 * the identity provider an organization's employees sign in through.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// liveOrgID is the workspace the live-key cases configure. The organization the
// shared fixture seeds carries the schema default of test, and the privacy
// interceptor hides a test workspace from a live credential, so a live caller
// needs one of its own to configure at all.
const liveOrgID = "org_siemens_live"

// seedLiveOrganization adds liveOrgID under a bypass, which is what provisioning
// does: a workspace belongs to an environment, and seeding one is not a request
// acting inside either.
func seedLiveOrganization(t *testing.T, factory *clientfactory.ClientFactory) {
	t.Helper()

	ctx := privacy.NewBypassContext(context.Background())
	_, err := factory.GetClient(ctx, "tnt_test", "").Organization.Create().
		SetID(liveOrgID).
		SetTenantID("tnt_test").
		SetName("Siemens AG").
		SetSlug("siemens-live").
		SetEnvironment(organization.EnvironmentLive).
		Save(ctx)
	if err != nil {
		t.Fatalf("seeding a live organization: %v", err)
	}
}

// connectionRequest builds a valid create request. Each case passes its own domain
// because a domain may back only one connection per tenant, so two connections
// sharing one would fail the exclusivity check rather than the guard under test.
func connectionRequest(orgID, domain, environment string, cert string) saml.CreateSAMLRequest {
	return saml.CreateSAMLRequest{
		OrganizationID: orgID,
		IDPEntityID:    testIdPEntityID,
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: cert,
		AllowedDomains: []string{domain},
		EnforceSSO:     true,
		Environment:    environment,
	}
}

// TestTestKeyCannotCreateALiveConnection covers the create the environment field
// opened up. The field is read from the request body, so without this check the
// weaker credential decides which environment it writes — and because the schema
// default here is live, it does so by supplying nothing at all.
func TestTestKeyCannotCreateALiveConnection(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, _, cleanup := setupTestSAMLService(t)
	defer cleanup()

	testCtx := privacy.NewContext(context.Background(), "tnt_test", "", "test")

	_, err := svc.CreateSAMLConnection(testCtx, "tnt_test", "usr_admin",
		connectionRequest("org_siemens", "siemens.com", "live", idp.certPEM), "127.0.0.1", "TestAgent")
	if !errors.Is(err, saml.ErrLiveKeyRequired) {
		t.Errorf("a test key naming live: got %v, want ErrLiveKeyRequired", err)
	}

	t.Run("an omitted environment is the same request", func(t *testing.T) {
		_, err := svc.CreateSAMLConnection(testCtx, "tnt_test", "usr_admin",
			connectionRequest("org_siemens", "siemens.de", "", idp.certPEM), "127.0.0.1", "TestAgent")
		if !errors.Is(err, saml.ErrLiveKeyRequired) {
			t.Errorf("a test key omitting environment: got %v, want ErrLiveKeyRequired", err)
		}
	})

	t.Run("its own test connection is unaffected", func(t *testing.T) {
		created, err := svc.CreateSAMLConnection(testCtx, "tnt_test", "usr_admin",
			connectionRequest("org_siemens", "siemens.at", "test", idp.certPEM), "127.0.0.1", "TestAgent")
		if err != nil {
			t.Fatalf("a test key configuring a test connection: %v", err)
		}
		if created.Environment != "test" {
			t.Errorf("stored environment %q, want \"test\"", created.Environment)
		}
	})
}

// TestTestKeyCannotChangeALiveConnection is the more serious half. A connection is
// the one entity carrying no environment predicate, so a test credential can read
// a live one by organization ID; editing its certificate would repoint an
// organization's production SSO at whatever identity provider the caller chose.
func TestTestKeyCannotChangeALiveConnection(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, factory, cleanup := setupTestSAMLService(t)
	defer cleanup()
	seedLiveOrganization(t, factory)

	liveCtx := privacy.NewContext(context.Background(), "tnt_test", "", "live")
	created, err := svc.CreateSAMLConnection(liveCtx, "tnt_test", "usr_admin",
		connectionRequest(liveOrgID, "siemens.com", "live", idp.certPEM), "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a live key configuring a live connection: %v", err)
	}

	testCtx := privacy.NewContext(context.Background(), "tnt_test", "", "test")
	hostile := "https://attacker.example.com/sso"

	_, err = svc.UpdateSAMLConnection(testCtx, "tnt_test", "usr_admin", liveOrgID,
		saml.UpdateSAMLRequest{IDPSSOURL: &hostile}, "127.0.0.1", "TestAgent")
	if !errors.Is(err, saml.ErrLiveKeyRequired) {
		t.Fatalf("a test key editing a live connection: got %v, want ErrLiveKeyRequired", err)
	}

	// Re-read rather than trust the refusal, because a status is only a refusal if
	// nothing was written behind it.
	reread, err := svc.GetSAMLConnection(liveCtx, "tnt_test", liveOrgID)
	if err != nil {
		t.Fatalf("re-reading the live connection: %v", err)
	}
	if reread.IDPSSOURL != created.IDPSSOURL {
		t.Errorf("the refused edit landed anyway: SSO URL is now %q", reread.IDPSSOURL)
	}

	t.Run("nor delete it", func(t *testing.T) {
		err := svc.DeleteSAMLConnection(testCtx, "tnt_test", "usr_admin", liveOrgID, "127.0.0.1", "TestAgent")
		if !errors.Is(err, saml.ErrLiveKeyRequired) {
			t.Fatalf("a test key deleting a live connection: got %v, want ErrLiveKeyRequired", err)
		}
		if _, err := svc.GetSAMLConnection(liveCtx, "tnt_test", liveOrgID); err != nil {
			t.Errorf("the connection was deleted despite the refusal: %v", err)
		}
	})
}

// TestTestKeyCannotPromoteItsOwnConnection closes the other route to a live
// connection. Owning the trial is not owning the promotion: the edit that moves a
// connection into live is the one that puts an identity provider in front of real
// employees, so it belongs to the live credential even when the row starts in test.
func TestTestKeyCannotPromoteItsOwnConnection(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, _, cleanup := setupTestSAMLService(t)
	defer cleanup()

	testCtx := privacy.NewContext(context.Background(), "tnt_test", "", "test")
	if _, err := svc.CreateSAMLConnection(testCtx, "tnt_test", "usr_admin",
		connectionRequest("org_siemens", "siemens.com", "test", idp.certPEM), "127.0.0.1", "TestAgent"); err != nil {
		t.Fatalf("a test key configuring a test connection: %v", err)
	}

	live := "live"
	_, err := svc.UpdateSAMLConnection(testCtx, "tnt_test", "usr_admin", "org_siemens",
		saml.UpdateSAMLRequest{Environment: &live}, "127.0.0.1", "TestAgent")
	if !errors.Is(err, saml.ErrLiveKeyRequired) {
		t.Fatalf("a test key promoting its own connection: got %v, want ErrLiveKeyRequired", err)
	}

	reread, err := svc.GetSAMLConnection(testCtx, "tnt_test", "org_siemens")
	if err != nil {
		t.Fatalf("re-reading the connection: %v", err)
	}
	if reread.Environment != "test" {
		t.Errorf("the refused promotion landed anyway: environment is now %q", reread.Environment)
	}

	t.Run("a live key promotes it", func(t *testing.T) {
		liveCtx := privacy.NewContext(context.Background(), "tnt_test", "", "live")
		promoted, err := svc.UpdateSAMLConnection(liveCtx, "tnt_test", "usr_admin", "org_siemens",
			saml.UpdateSAMLRequest{Environment: &live}, "127.0.0.1", "TestAgent")
		if err != nil {
			t.Fatalf("a live key promoting a test connection: %v", err)
		}
		if promoted.Environment != "live" {
			t.Errorf("promoted environment %q, want \"live\"", promoted.Environment)
		}
	})
}

// TestBypassAndUnscopedCallersAreExempt covers provisioning and seeding, neither of
// which is a credential acting inside an environment. Every HTTP entry point
// installs a scope, so refusing an absent one would break the paths that legitimately
// address both environments while protecting nothing.
func TestBypassAndUnscopedCallersAreExempt(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, factory, cleanup := setupTestSAMLService(t)
	defer cleanup()
	seedLiveOrganization(t, factory)

	bypass := privacy.NewBypassContext(context.Background())
	if _, err := svc.CreateSAMLConnection(bypass, "tnt_test", "usr_admin",
		connectionRequest("org_siemens", "siemens.com", "live", idp.certPEM), "127.0.0.1", "TestAgent"); err != nil {
		t.Errorf("a bypass context configuring a live connection: %v", err)
	}

	// A tenant with no environment addresses both at once, which is not a place the
	// guard can decide anything.
	unscoped := privacy.NewContext(context.Background(), "tnt_test", "", "")
	if _, err := svc.CreateSAMLConnection(unscoped, "tnt_test", "usr_admin",
		connectionRequest(liveOrgID, "siemens.de", "live", idp.certPEM), "127.0.0.1", "TestAgent"); err != nil {
		t.Errorf("a context naming no environment configuring a live connection: %v", err)
	}
}
