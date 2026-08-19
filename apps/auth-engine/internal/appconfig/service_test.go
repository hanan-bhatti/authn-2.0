/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/appconfig/service_test.go
 * Tier: Business Logic Layer / Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package appconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

// pollutedBrandingColumn is a branding column holding both the public
// presentational keys and the private ones the schema shares the column with.
//
// The stored column is a free-form JSON object, so this is what a real one looks
// like once a tenant has configured email templates alongside its colours.
func pollutedBrandingColumn() map[string]interface{} {
	return map[string]interface{}{
		"logo_url":      "https://cdn.acme.example/logo.svg",
		"primary_color": "#1a73e8",
		"app_name":      "Acme Identity",

		// Not public, and sharing the column with what is.
		"email_templates": map[string]interface{}{
			"welcome": "Escalate to security@acme-internal.example, bypass ACME-2024",
		},
		"smtp_password":       "hunter2-should-never-ship",
		"internal_notes":      "migrating off the legacy IdP on the 3rd",
		"webhook_signing_key": "whsec_should_never_ship",
	}
}

// fullyPopulatedDocument builds a bootstrap document from maximally populated
// inputs, so that anything the projections do carry through appears in the result.
func fullyPopulatedDocument() AppConfig {
	socialColumn := map[string]interface{}{
		"google": map[string]interface{}{
			"enabled":                 true,
			"client_id":               "1234567890-abcdef.apps.googleusercontent.com",
			"client_secret_encrypted": "Z0FBQUFBQm9nb29nbGVzZWNyZXQ=",
		},
		"github": map[string]interface{}{
			"enabled":                 true,
			"client_id":               "Iv1.deadbeefdeadbeef",
			"client_secret_encrypted": "Z0FBQUFBQm9naXRodWJzZWNyZXQ=",
		},
		"apple": map[string]interface{}{
			"enabled":                 false,
			"client_id":               "com.acme.signin",
			"client_secret_encrypted": "Z0FBQUFBQm9hcHBsZXNlY3JldA==",
		},
	}

	return AppConfig{
		Application: ApplicationInfo{
			ID:          "app_01HQ8ACME",
			Name:        "Acme Web",
			Environment: "live",
		},
		Tenant:            TenantInfo{Name: "Acme Corp", Slug: "acme"},
		Branding:          decodeBranding(pollutedBrandingColumn()),
		SignInMethods:     SignInMethods{Password: true, MagicLink: true, Passkey: true, EnterpriseSSO: true, SocialProviders: enabledProviders(socialColumn)},
		SecondFactors:     SecondFactors{TOTP: true, SMS: true, Passkey: true, RecoveryCodes: true, Push: true},
		PasswordRules:     passwordRules(policy.DefaultPasswordPolicy()),
		EmailVerification: emailVerification(policy.DefaultSecurityPolicy()),
		AccountRecovery:   accountRecovery(policy.DefaultRecoveryPolicy(), true),
	}
}

// TestAppConfigWithholdsSensitiveFields serialises a fully populated bootstrap
// document and requires that none of the withheld fields appear in it.
//
// This endpoint sits behind a publishable key, which ships in browser bundles: the
// response is readable by anyone who views the source of a sign-in page. So the
// test is written against the wire format rather than against the structs — a
// contributor who embeds a whole policy struct, or widens the branding type to
// echo the stored column, breaks this test even though every individual
// projection still compiles.
func TestAppConfigWithholdsSensitiveFields(t *testing.T) {
	body, err := json.Marshal(fullyPopulatedDocument())
	if err != nil {
		t.Fatalf("marshalling the document failed: %v", err)
	}
	wire := string(body)

	// Each key is withheld for a stated reason, and the reason is the test's
	// documentation: a future contributor deciding to publish one of these should
	// have to argue with the sentence next to it.
	forbiddenKeys := map[string]string{
		// Recovery pacing: an attacker who reads these can stay under every
		// threshold instead of guessing where they are.
		"lockout_schedule":              "lets an attacker pace recovery attempts under the lockout",
		"lockout_reset_days":            "tells an attacker how long to wait for a clean slate",
		"max_proof_attempts_per_window": "tells an attacker exactly how many attempts are free",
		"freeze_window_hours":           "tells an attacker how long the real owner has to intervene",
		"claim_token_ttl_minutes":       "tells an attacker the window to use a stolen claim token",
		"trusted_device_window_days":    "tells an attacker how long a compromised device stays trusted",
		"ipv4_subnet_bits":              "tells an attacker how coarsely their source address is grouped",
		"ipv6_subnet_bits":              "tells an attacker how coarsely their source address is grouped",

		// Token handling: tells a holder of a stolen refresh token whether replaying
		// it is quiet or ends every session.
		"token_reuse_policy": "tells an attacker whether replaying a stolen token is noisy",

		// Application allowlists: the lists an open-redirect or cross-origin attempt
		// is measured against.
		"allowed_cors_origins": "enumerates the origins an attacker would otherwise guess",
		"exact_redirect_uris":  "enumerates the redirect targets an attacker would otherwise guess",

		// Tenant internals.
		"domain_verification_token": "is the DNS proof of domain ownership",
		"first_admin_claimed":       "reveals whether signing up still grants tenant_admin",
		"custom_domain":             "is not needed to render a sign-in page",

		// Provider credentials: the engine performs the redirect itself, so a
		// browser never needs either of these.
		"client_id":               "is a credential no browser needs",
		"client_secret_encrypted": "is a credential no browser needs",
		"client_secret":           "is a credential no browser needs",

		// Column neighbours that are not branding.
		"email_templates":     "shares the branding column but is not public",
		"smtp_password":       "shares the branding column but is a secret",
		"internal_notes":      "shares the branding column but is internal",
		"webhook_signing_key": "shares the branding column but is a secret",
	}

	for key, why := range forbiddenKeys {
		if strings.Contains(wire, `"`+key+`"`) {
			t.Errorf("the public bootstrap document carries %q, which %s\nbody: %s", key, why, wire)
		}
	}

	// Values, not only keys: a projection that renamed a field on the way out would
	// pass the key check while still publishing the secret.
	forbiddenValues := []string{
		"hunter2-should-never-ship",
		"whsec_should_never_ship",
		"security@acme-internal.example",
		"migrating off the legacy IdP",
		"apps.googleusercontent.com",
		"Iv1.deadbeefdeadbeef",
		"Z0FBQUFBQm9n",
	}
	for _, value := range forbiddenValues {
		if strings.Contains(wire, value) {
			t.Errorf("the public bootstrap document leaks the value %q\nbody: %s", value, wire)
		}
	}
}

// TestAppConfigCarriesWhatASignInPageNeeds is the other half of the leak guard: a
// document narrowed until it is safe is worthless if the page cannot render from
// it. Every key here is one a sign-in page reads.
func TestAppConfigCarriesWhatASignInPageNeeds(t *testing.T) {
	body, err := json.Marshal(fullyPopulatedDocument())
	if err != nil {
		t.Fatalf("marshalling the document failed: %v", err)
	}
	wire := string(body)

	required := []string{
		"application", "environment",
		"branding", "logo_url", "primary_color", "app_name",
		"sign_in_methods", "social_providers", "magic_link", "passkey", "enterprise_sso",
		"second_factors", "totp", "recovery_codes",
		"password_rules", "min_length", "max_length", "require_numeric", "enforced",
		"email_verification", "required", "mode",
		"account_recovery", "guardians", "email_otp", "min_guardians", "max_guardians",
	}
	for _, key := range required {
		if !strings.Contains(wire, `"`+key+`"`) {
			t.Errorf("the bootstrap document is missing %q, which a sign-in page needs to render", key)
		}
	}
}

// TestDecodeBrandingNarrowsTheStoredColumn checks the mechanism the leak guard
// relies on: the stored column is free-form, and unmarshalling it into a fixed
// struct is what drops the keys nobody designed.
func TestDecodeBrandingNarrowsTheStoredColumn(t *testing.T) {
	b := decodeBranding(pollutedBrandingColumn())

	if b.LogoURL != "https://cdn.acme.example/logo.svg" {
		t.Errorf("the public keys should survive, got logo_url %q", b.LogoURL)
	}
	if b.AppName != "Acme Identity" {
		t.Errorf("the public keys should survive, got app_name %q", b.AppName)
	}

	// The narrowing is structural: Branding has no field for the private keys, so
	// there is nothing to assert against beyond the serialised form.
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshalling branding failed: %v", err)
	}
	if strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "email_templates") {
		t.Errorf("decodeBranding carried a private key through: %s", body)
	}
}

// TestDecodeBrandingDegradesRatherThanFails checks that an unreadable column
// yields empty branding. This is read on the first request a sign-in page makes,
// so a parse failure must cost the page its styling and not its ability to render.
func TestDecodeBrandingDegradesRatherThanFails(t *testing.T) {
	cases := []struct {
		name   string
		stored map[string]interface{}
	}{
		{"nil column", nil},
		{"empty column", map[string]interface{}{}},
		// A key whose stored type does not match the struct fails the whole
		// unmarshal, which is the case that must not panic or propagate.
		{"wrongly typed value", map[string]interface{}{"logo_url": []int{1, 2, 3}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeBranding(tc.stored); got != (Branding{}) {
				t.Errorf("decodeBranding(%s) should degrade to empty branding, got %+v", tc.name, got)
			}
		})
	}
}

// TestEnabledProvidersReportsNamesOnly checks that only switched-on providers are
// named, that the order is stable, and that nothing but the name crosses over.
//
// The order matters beyond tidiness: the response is cacheable, and a map's
// iteration order would make each response differ from the last.
func TestEnabledProvidersReportsNamesOnly(t *testing.T) {
	stored := map[string]interface{}{
		"google":    map[string]interface{}{"enabled": true, "client_id": "g-id"},
		"github":    map[string]interface{}{"enabled": true, "client_id": "gh-id"},
		"apple":     map[string]interface{}{"enabled": false, "client_id": "ap-id"},
		"discord":   map[string]interface{}{"client_id": "d-id"},
		"malformed": "not an object",
	}

	got := enabledProviders(stored)
	want := []string{"github", "google"}

	if len(got) != len(want) {
		t.Fatalf("enabledProviders() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("enabledProviders() = %v, want %v (sorted, enabled only)", got, want)
		}
	}
}

// TestPasswordRulesPublishTheEnforcedBounds checks that the rules a page is told
// are the rules the engine applies.
//
// A tenant can store a minimum below the engine's own floor. Publishing the stored
// value would produce a form that accepts a password the API then rejects, which
// reads to the user as a broken site rather than as a policy.
func TestPasswordRulesPublishTheEnforcedBounds(t *testing.T) {
	weakened := policy.PasswordPolicy{
		EnforcementMode: "require",
		MinLength:       4,
		MaxLength:       0,
		RequireNumeric:  true,
	}

	rules := passwordRules(weakened)

	if rules.MinLength != policy.MinPasswordLength {
		t.Errorf("min_length = %d, want the enforced floor %d: a page told 4 would accept a password the API refuses",
			rules.MinLength, policy.MinPasswordLength)
	}
	if rules.MaxLength != policy.MaxPasswordLength {
		t.Errorf("max_length = %d, want %d", rules.MaxLength, policy.MaxPasswordLength)
	}
	if !rules.Enforced {
		t.Error("enforced should be true under the \"require\" mode")
	}

	// "notify" accepts a non-compliant password and reports what is missing, so a
	// page should warn rather than block.
	notify := policy.DefaultPasswordPolicy()
	notify.EnforcementMode = "notify"
	if passwordRules(notify).Enforced {
		t.Error("enforced should be false under the \"notify\" mode, so a page warns instead of blocking")
	}
}

// TestRecoveryAndSecondFactorsFollowDeliveryCapability checks that a method the
// deployment cannot deliver is not offered.
//
// A tenant can enable phone recovery on a deployment with no SMS provider
// configured. Offering it produces a button that sends a code which never
// arrives, and a user who waits for it rather than trying another method.
func TestRecoveryAndSecondFactorsFollowDeliveryCapability(t *testing.T) {
	everythingOn := policy.DefaultRecoveryPolicy()

	withSMS := accountRecovery(everythingOn, true)
	if !withSMS.PhoneOTP {
		t.Error("phone_otp should be offered when the tenant enables it and SMS can be delivered")
	}

	withoutSMS := accountRecovery(everythingOn, false)
	if withoutSMS.PhoneOTP {
		t.Error("phone_otp must not be offered when the deployment has no SMS driver")
	}
	// The other methods are unaffected: only the SMS-delivered one depends on the
	// driver.
	if !withoutSMS.EmailOTP || !withoutSMS.Guardians || !withoutSMS.OldPassword || !withoutSMS.SecurityQuestions {
		t.Errorf("an absent SMS driver must not disable the other recovery methods, got %+v", withoutSMS)
	}
}

// TestSMSDeliverableTreatsAnUnnamedDriverAsUnavailable checks the fail-closed
// direction of the capability check.
//
// config.Load resolves SMS_DRIVER to one of the supported values, so an empty
// field only appears in a Config assembled in code. The check still has to handle
// it, because the alternative reading — anything that is not "noop" can send —
// turns an unset field into a page offering a code nothing will deliver.
func TestSMSDeliverableTreatsAnUnnamedDriverAsUnavailable(t *testing.T) {
	cases := []struct {
		driver string
		want   bool
	}{
		{"", false},
		{noopSMSDriver, false},
		{"twilio", true},
		{"aws_sns", true},
	}

	for _, tc := range cases {
		t.Run("driver="+tc.driver, func(t *testing.T) {
			svc := &Service{cfg: &config.Config{SMSDriver: tc.driver}}
			if got := svc.smsDeliverable(); got != tc.want {
				t.Errorf("smsDeliverable() with driver %q = %v, want %v", tc.driver, got, tc.want)
			}
		})
	}
}

// TestEmailVerificationDefaultsTheMode checks that an empty stored mode is
// reported as "soft" rather than as an empty string a client would have to
// interpret. Soft is the documented default, and it is the permissive of the two,
// so reporting it never has a page block a user the engine would admit.
func TestEmailVerificationDefaultsTheMode(t *testing.T) {
	got := emailVerification(policy.SecurityPolicy{RequireEmailVerification: true})
	if got.Mode != "soft" {
		t.Errorf("mode = %q, want \"soft\" for an unset stored value", got.Mode)
	}
	if !got.Required {
		t.Error("required should follow the stored policy")
	}
}
