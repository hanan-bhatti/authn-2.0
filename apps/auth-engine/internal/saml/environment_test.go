/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/environment_test.go
 * Tier: Automated Testing Layer / Unit Tests
 *
 * Description: Tests for the environment a SAML connection provisions into —
 *              that a connection pointed at test mints sandbox accounts, that it
 *              cannot reach or overwrite the live account sharing an address with
 *              one, that promoting a trialled connection changes where subsequent
 *              sign-ins land, and that an unrecognised environment is refused
 *              rather than guessed.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

// subjectEmail is the address every assertion in this file asserts. It is the one
// address that matters here: the whole question is what happens when the same
// person exists, or does not exist, in each environment.
const subjectEmail = "alex@siemens.com"

// newEnvironmentFixture provisions a service whose one SAML connection provisions
// into the named environment.
//
// It exists alongside newACSFixture rather than replacing it because the other ACS
// tests are about whether an assertion is trusted at all, and pinning them to an
// environment would say nothing about that.
func newEnvironmentFixture(t *testing.T, idp *signingIdentity, environment string) (*saml.Service, context.Context, *clientfactory.ClientFactory, func()) {
	t.Helper()

	svc, factory, cleanup := setupTestSAMLService(t)
	ctx := privacy.NewBypassContext(context.Background())

	_, err := svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    testIdPEntityID,
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: idp.certPEM,
		AllowedDomains: []string{"siemens.com"},
		EnforceSSO:     true,
		Environment:    environment,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		cleanup()
		t.Fatalf("failed to create a %s SAML connection: %v", environment, err)
	}

	return svc, ctx, factory, cleanup
}

// signIn posts a correctly signed assertion for subjectEmail through svc.
func signIn(t *testing.T, svc *saml.Service, ctx context.Context, idp *signingIdentity) *saml.ACSResult {
	t.Helper()

	payload := base64.StdEncoding.EncodeToString(
		[]byte(idp.sign(t, buildACSResponse(acsResponseOptions{nameID: subjectEmail}))))

	result, err := svc.ProcessACS(ctx, payload, "", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a correctly signed assertion must be accepted, got: %v", err)
	}
	return result
}

// TestConnectionEnvironmentDecidesProvisioning covers the guarantee the field
// exists for: an administrator trialling a new identity provider gets sandbox
// accounts, and one configuring their real one gets real accounts.
func TestConnectionEnvironmentDecidesProvisioning(t *testing.T) {
	for _, environment := range []string{"test", "live"} {
		t.Run(environment, func(t *testing.T) {
			idp := newSigningIdentity(t)
			svc, ctx, _, cleanup := newEnvironmentFixture(t, idp, environment)
			defer cleanup()

			result := signIn(t, svc, ctx, idp)

			if got := string(result.User.Environment); got != environment {
				t.Errorf("a %s connection must provision a %s account, got %q", environment, environment, got)
			}
			// The session and its access token are issued against the same
			// environment, so a sandbox sign-in cannot be presented as a live one.
			if result.Environment != environment {
				t.Errorf("expected the session to be issued against %s, got %q", environment, result.Environment)
			}
		})
	}
}

// TestTestConnectionCannotReachLiveAccount is the isolation this split exists to
// provide. An engineer trialling Okta signs in as themselves; their real account,
// with its real roles and organization memberships, must not be what the trial
// hands them a session for.
func TestTestConnectionCannotReachLiveAccount(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, factory, cleanup := newEnvironmentFixture(t, idp, "test")
	defer cleanup()

	liveUser, err := factory.GetClient(ctx, "tnt_test", "live").User.Create().
		SetID(idgen.New("usr")).
		SetTenantID("tnt_test").
		SetEnvironment(user.EnvironmentLive).
		SetEmail(subjectEmail).
		SetEmailVerified(true).
		SetName("Alex Live").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed seeding the live account: %v", err)
	}

	result := signIn(t, svc, ctx, idp)

	if result.User.ID == liveUser.ID {
		t.Fatal("a test connection signed the caller into the live account")
	}
	if string(result.User.Environment) != "test" {
		t.Errorf("expected a test account, got environment %q", result.User.Environment)
	}

	// The live row is re-read rather than trusted from the seed, because the
	// failure this guards against is a JIT provision that updates the existing
	// account instead of creating a sibling.
	reread, err := factory.GetClient(ctx, "tnt_test", "live").User.Get(ctx, liveUser.ID)
	if err != nil {
		t.Fatalf("the live account must still exist: %v", err)
	}
	if reread.Name != "Alex Live" || string(reread.Environment) != "live" {
		t.Errorf("the live account was modified by a test sign-in: %+v", reread)
	}
}

// TestRepeatedSignInReusesTheSameAccount covers the lookup that keeps a subject
// from accumulating one account per sign-in, which the unique index on
// (tenant, environment, email) would refuse outright on the second attempt.
func TestRepeatedSignInReusesTheSameAccount(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, _, cleanup := newEnvironmentFixture(t, idp, "test")
	defer cleanup()

	first := signIn(t, svc, ctx, idp)
	second := signIn(t, svc, ctx, idp)

	if first.User.ID != second.User.ID {
		t.Errorf("the same subject must resolve to one account, got %q then %q", first.User.ID, second.User.ID)
	}
}

// TestPromotingConnectionMovesSubsequentSignIns covers the trial-then-promote
// path. The accounts minted during the trial stay in test, which is the intended
// outcome: a sandbox account is not a real one.
func TestPromotingConnectionMovesSubsequentSignIns(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, _, cleanup := newEnvironmentFixture(t, idp, "test")
	defer cleanup()

	trial := signIn(t, svc, ctx, idp)
	if string(trial.User.Environment) != "test" {
		t.Fatalf("the trial sign-in should have produced a test account, got %q", trial.User.Environment)
	}

	live := "live"
	updated, err := svc.UpdateSAMLConnection(ctx, "tnt_test", "usr_admin", "org_siemens",
		saml.UpdateSAMLRequest{Environment: &live}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("promoting the connection must succeed: %v", err)
	}
	if updated.Environment != "live" {
		t.Errorf("expected the promoted connection to report live, got %q", updated.Environment)
	}

	promoted := signIn(t, svc, ctx, idp)
	if string(promoted.User.Environment) != "live" {
		t.Errorf("a sign-in after promotion must land in live, got %q", promoted.User.Environment)
	}
	if promoted.User.ID == trial.User.ID {
		t.Error("the promotion moved the trial account into live rather than leaving it in test")
	}
}

// TestSubjectPresentInBothEnvironmentsFollowsTheConnection is the direction a live
// preference would break. With an account in each environment, a test connection
// must address the test one; anything that treats live as the better answer would
// hand a trial run a real employee's session.
func TestSubjectPresentInBothEnvironmentsFollowsTheConnection(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, factory, cleanup := newEnvironmentFixture(t, idp, "test")
	defer cleanup()

	seeded := map[user.Environment]string{}
	for _, env := range []user.Environment{user.EnvironmentTest, user.EnvironmentLive} {
		created, err := factory.GetClient(ctx, "tnt_test", string(env)).User.Create().
			SetID(idgen.New("usr")).
			SetTenantID("tnt_test").
			SetEnvironment(env).
			SetEmail(subjectEmail).
			SetEmailVerified(true).
			Save(ctx)
		if err != nil {
			t.Fatalf("failed seeding the %s account: %v", env, err)
		}
		seeded[env] = created.ID
	}

	result := signIn(t, svc, ctx, idp)

	if result.User.ID != seeded[user.EnvironmentTest] {
		t.Errorf("a test connection must address the test account %q, got %q",
			seeded[user.EnvironmentTest], result.User.ID)
	}
}

// TestCreateDefaultsToLive covers the default an existing client relies on: a
// request written before this field existed configures the real identity provider,
// not a sandbox one.
func TestCreateDefaultsToLive(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, _, cleanup := setupTestSAMLService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	created, err := svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    testIdPEntityID,
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: idp.certPEM,
		AllowedDomains: []string{"siemens.com"},
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a request omitting environment must be accepted: %v", err)
	}
	if created.Environment != "live" {
		t.Errorf("expected an omitted environment to mean live, got %q", created.Environment)
	}
}

// TestRejectsUnknownEnvironment covers the refusal that keeps a typo from being
// resolved into one of the two real environments. "prod" quietly meaning test
// would send an organization's employees into a sandbox.
func TestRejectsUnknownEnvironment(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, _, cleanup := setupTestSAMLService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	_, err := svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    testIdPEntityID,
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: idp.certPEM,
		AllowedDomains: []string{"siemens.com"},
		Environment:    "prod",
	}, "127.0.0.1", "TestAgent")
	if !errors.Is(err, saml.ErrInvalidEnvironment) {
		t.Errorf("expected ErrInvalidEnvironment on create, got %v", err)
	}

	_, err = svc.CreateSAMLConnection(ctx, "tnt_test", "usr_admin", saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    testIdPEntityID,
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: idp.certPEM,
		AllowedDomains: []string{"siemens.com"},
		Environment:    "live",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed creating the connection the update case needs: %v", err)
	}

	staging := "staging"
	_, err = svc.UpdateSAMLConnection(ctx, "tnt_test", "usr_admin", "org_siemens",
		saml.UpdateSAMLRequest{Environment: &staging}, "127.0.0.1", "TestAgent")
	if !errors.Is(err, saml.ErrInvalidEnvironment) {
		t.Errorf("expected ErrInvalidEnvironment on update, got %v", err)
	}
}

// TestEnvironmentIsCaseAndSpaceInsensitive covers the normalization a value
// pasted from a console form goes through, so " Live " configures live rather than
// being refused.
func TestEnvironmentIsCaseAndSpaceInsensitive(t *testing.T) {
	req := saml.CreateSAMLRequest{
		OrganizationID: "org_siemens",
		IDPEntityID:    testIdPEntityID,
		IDPSSOURL:      "https://siemens.okta.com/app/sso/saml",
		IDPCertificate: sampleCert,
		AllowedDomains: []string{"siemens.com"},
		Environment:    "  TEST  ",
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("a padded, uppercased environment must normalize: %v", err)
	}
	if req.Environment != "test" {
		t.Errorf("expected %q to normalize to \"test\", got %q", "  TEST  ", req.Environment)
	}
}
