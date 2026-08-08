/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/config/config_test.go
 * Tier: Configuration Layer / Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package config

import (
	"strings"
	"testing"
	"time"
)

// withEnv sets environment variables for one test and restores the previous
// state afterwards, so tests cannot leak configuration into one another.
func withEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for key, value := range vars {
		t.Setenv(key, value)
	}
}

// baseProductionEnv is the minimum a production deployment must supply. Tests
// start from this and override the single variable under examination.
func baseProductionEnv() map[string]string {
	return map[string]string{
		"APP_ENV":               "production",
		"DATABASE_URL":          "postgres://user:pass@db:5432/authn",
		"REDIS_URL":             "redis://cache:6379",
		"AUTHN_ENCRYPTION_KEY":  strings.Repeat("a", 32),
		"AUTHN_API_KEY_PEPPER":  strings.Repeat("b", 32),
		"APP_BASE_URL":          "https://auth.example.com",
		"ISSUER_URL":            "https://auth.example.com",
		"CORS_ALLOWED_ORIGINS":  "https://app.example.com",
		"WEBAUTHN_RP_ID":        "example.com",
		"WEBAUTHN_RP_ORIGINS":   "https://app.example.com",
		"DATABASE_AUTO_MIGRATE": "false",
	}
}

func TestLoadAppliesDocumentedDefaults(t *testing.T) {
	withEnv(t, map[string]string{"APP_ENV": "development"})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"Port", cfg.Port, 8080},
		{"RateLimitEnabled", cfg.RateLimitEnabled, true},
		{"RateLimitMaxAttempts", cfg.RateLimitMaxAttempts, 5},
		{"RateLimitWindow", cfg.RateLimitWindow, 15 * time.Minute},
		{"AccessTokenTTL", cfg.AccessTokenTTL, 15 * time.Minute},
		{"RefreshTokenTTL", cfg.RefreshTokenTTL, 720 * time.Hour},
		{"OAuthCodeTTL", cfg.OAuthCodeTTL, 10 * time.Minute},
		{"OrgMetadataMaxBytes", cfg.OrgMetadataMaxBytes, 10 * 1024},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// A malformed value must stop startup rather than silently reverting to a
// default: a typo in PORT should never mean "listen somewhere else".
func TestLoadRejectsMalformedValues(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"non-numeric port", map[string]string{"PORT": "80o0"}},
		{"port out of range", map[string]string{"PORT": "70000"}},
		{"port zero", map[string]string{"PORT": "0"}},
		{"bad duration", map[string]string{"ACCESS_TOKEN_TTL": "15 minutes"}},
		{"negative duration", map[string]string{"ACCESS_TOKEN_TTL": "-5m"}},
		{"bad boolean", map[string]string{"RATELIMIT_ENABLED": "yes-please"}},
		{"zero max attempts", map[string]string{"RATELIMIT_MAX_ATTEMPTS": "0"}},
		{"relative base URL", map[string]string{"APP_BASE_URL": "/auth"}},
		{"base URL without scheme", map[string]string{"APP_BASE_URL": "auth.example.com"}},
		{"unknown email driver", map[string]string{"EMAIL_DRIVER": "carrier-pigeon"}},
		{"origin with a path", map[string]string{"CORS_ALLOWED_ORIGINS": "https://app.example.com/callback"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEnv(t, map[string]string{"APP_ENV": "development"})
			withEnv(t, tc.env)

			if _, err := Load(); err == nil {
				t.Fatalf("Load() should have failed for %s", tc.name)
			}
		})
	}
}

// Reflecting any origin while allowing credentials lets any site a signed-in
// user visits call this API with their cookies and read the response.
func TestValidateRejectsWildcardOriginWithCredentials(t *testing.T) {
	cfg := &Config{
		Env:                  EnvDevelopment,
		AppBaseURL:           "http://localhost:8080",
		Issuer:               "http://localhost:8080",
		CORSAllowedOrigins:   []string{"*"},
		CORSAllowCredentials: true,
		WebAuthnRPID:         "localhost",
		AccessTokenTTL:       15 * time.Minute,
		RefreshTokenTTL:      720 * time.Hour,
		SessionGracePeriod:   10 * time.Second,
		OAuthCodeTTL:         10 * time.Minute,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("a wildcard origin with credentials enabled must be rejected")
	}
	if !strings.Contains(err.Error(), "CORS_ALLOWED_ORIGINS") {
		t.Errorf("error should name the offending variable, got: %v", err)
	}

	// The same wildcard is acceptable once credentials are off.
	cfg.CORSAllowCredentials = false
	if err := cfg.Validate(); err != nil {
		t.Errorf("a wildcard origin without credentials is valid, got: %v", err)
	}
}

func TestValidateProductionRequirements(t *testing.T) {
	cases := []struct {
		name        string
		override    map[string]string
		wantMessage string
	}{
		{
			name:        "plaintext base URL",
			override:    map[string]string{"APP_BASE_URL": "http://auth.example.com"},
			wantMessage: "APP_BASE_URL",
		},
		{
			name:        "wildcard origin",
			override:    map[string]string{"CORS_ALLOWED_ORIGINS": "*"},
			wantMessage: "CORS_ALLOWED_ORIGINS",
		},
		{
			name:        "localhost passkey domain",
			override:    map[string]string{"WEBAUTHN_RP_ID": "localhost", "WEBAUTHN_RP_ORIGINS": "http://localhost:3000"},
			wantMessage: "WEBAUTHN_RP_ID",
		},
		{
			name:        "auto migration enabled",
			override:    map[string]string{"DATABASE_AUTO_MIGRATE": "true"},
			wantMessage: "DATABASE_AUTO_MIGRATE",
		},
		{
			name: "encryption key reused as pepper",
			override: map[string]string{
				"AUTHN_ENCRYPTION_KEY": strings.Repeat("c", 32),
				"AUTHN_API_KEY_PEPPER": strings.Repeat("c", 32),
			},
			wantMessage: "must be different",
		},
		{
			name:        "short encryption key",
			override:    map[string]string{"AUTHN_ENCRYPTION_KEY": "too-short"},
			wantMessage: "AUTHN_ENCRYPTION_KEY",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEnv(t, baseProductionEnv())
			withEnv(t, tc.override)

			_, err := Load()
			if err == nil {
				t.Fatalf("production config with %s must be rejected", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Errorf("error should mention %q, got: %v", tc.wantMessage, err)
			}
		})
	}
}

// Missing infrastructure has no safe default in production, but development
// must still start with no setup at all.
func TestProductionRequiresInfrastructure(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_ENV":              "production",
		"APP_BASE_URL":         "https://auth.example.com",
		"ISSUER_URL":           "https://auth.example.com",
		"CORS_ALLOWED_ORIGINS": "https://app.example.com",
		"WEBAUTHN_RP_ID":       "example.com",
		"WEBAUTHN_RP_ORIGINS":  "https://app.example.com",
		"DATABASE_URL":         "",
		"REDIS_URL":            "",
		"AUTHN_ENCRYPTION_KEY": "",
		"AUTHN_API_KEY_PEPPER": "",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("production without a database, cache or secrets must be rejected")
	}
	for _, want := range []string{"DATABASE_URL", "REDIS_URL", "AUTHN_ENCRYPTION_KEY", "AUTHN_API_KEY_PEPPER"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s, got: %v", want, err)
		}
	}
}

func TestDevelopmentStartsWithoutConfiguration(t *testing.T) {
	withEnv(t, map[string]string{"APP_ENV": "development"})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("development must start with no configuration, got: %v", err)
	}
	if cfg.DatabaseURL == "" {
		t.Error("development should default to a local database")
	}
	if !cfg.DatabaseAutoMigrate {
		t.Error("development should migrate automatically so a fresh clone runs")
	}
}

// A passkey origin that does not belong to the relying-party domain fails in
// the browser with no server-side error, so it is caught at startup instead.
func TestValidateWebAuthnOriginsMatchRelyingParty(t *testing.T) {
	withEnv(t, baseProductionEnv())
	withEnv(t, map[string]string{
		"WEBAUTHN_RP_ID":      "example.com",
		"WEBAUTHN_RP_ORIGINS": "https://app.example.com,https://app.attacker.test",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("a passkey origin outside the relying-party domain must be rejected")
	}
	if !strings.Contains(err.Error(), "attacker.test") {
		t.Errorf("error should identify the offending origin, got: %v", err)
	}
}

func TestValidateTokenLifetimeOrdering(t *testing.T) {
	withEnv(t, baseProductionEnv())
	withEnv(t, map[string]string{
		"ACCESS_TOKEN_TTL":  "48h",
		"REFRESH_TOKEN_TTL": "24h",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("an access token outliving its refresh token must be rejected")
	}
	if !strings.Contains(err.Error(), "ACCESS_TOKEN_TTL") {
		t.Errorf("error should name the offending variable, got: %v", err)
	}
}

// A selected provider without credentials means sign-up succeeds while the
// verification email silently never sends.
func TestValidateDeliveryCredentials(t *testing.T) {
	withEnv(t, map[string]string{
		"APP_ENV":        "development",
		"EMAIL_DRIVER":   "resend",
		"RESEND_API_KEY": "",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("EMAIL_DRIVER=resend without an API key must be rejected")
	}
	if !strings.Contains(err.Error(), "RESEND_API_KEY") {
		t.Errorf("error should name the missing credential, got: %v", err)
	}
}

// Refresh-token cookies must carry Secure on every TLS origin, and only
// plaintext development opts out. A false negative ships long-lived tokens in
// cleartext; a false positive silently breaks local development.
func TestCookieSecureFollowsBaseURLScheme(t *testing.T) {
	cases := []struct {
		name       string
		appBaseURL string
		want       bool
	}{
		{"https production domain", "https://auth.acme.com", true},
		{"https with port", "https://localhost:8443", true},
		{"http localhost dev", "http://localhost:8080", false},
		{"http lan host", "http://192.168.1.20:8080", false},
		{"empty falls back to insecure", "", false},
		// Guards against a naive strings.Contains("https") check.
		{"http host merely containing https", "http://https.example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{AppBaseURL: tc.appBaseURL}
			if got := cfg.CookieSecure(); got != tc.want {
				t.Errorf("CookieSecure() with AppBaseURL=%q = %v, want %v",
					tc.appBaseURL, got, tc.want)
			}
		})
	}
}

func TestDerivedURLs(t *testing.T) {
	cfg := &Config{
		Host:                      "0.0.0.0",
		Port:                      8080,
		AppBaseURL:                "https://auth.example.com",
		SAMLAssertionConsumerPath: "/v1/saml/acs",
	}

	if got, want := cfg.Address(), "0.0.0.0:8080"; got != want {
		t.Errorf("Address() = %q, want %q", got, want)
	}
	if got, want := cfg.SocialCallbackURL("google"),
		"https://auth.example.com/v1/client/auth/social/google/callback"; got != want {
		t.Errorf("SocialCallbackURL() = %q, want %q", got, want)
	}
	if got, want := cfg.SAMLAssertionConsumerURL(),
		"https://auth.example.com/v1/saml/acs"; got != want {
		t.Errorf("SAMLAssertionConsumerURL() = %q, want %q", got, want)
	}
}
