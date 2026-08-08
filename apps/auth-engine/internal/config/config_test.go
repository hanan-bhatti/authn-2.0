package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_Defaults(t *testing.T) {
	// Temporarily clear environment variables to test defaults
	envKeys := []string{
		"AUTHN_RATELIMIT_ENABLED",
		"AUTHN_RATELIMIT_MAX_ATTEMPTS",
		"AUTHN_RATELIMIT_WINDOW_SECONDS",
		"AUTHN_RATELIMIT_BACKOFF_SCHEDULE",
		"AUTHN_RATELIMIT_VIOLATION_RESET_DAYS",
	}
	for _, key := range envKeys {
		os.Unsetenv(key)
	}
	os.Setenv("AUTHN_RATELIMIT_ENABLED", "true")

	cfg, err := LoadAndValidateConfig()
	if err != nil {
		t.Fatalf("unexpected config load error: %v", err)
	}

	if !cfg.RateLimitEnabled {
		t.Errorf("expected RateLimitEnabled default true, got false")
	}
	if cfg.RateLimitMaxAttempts != 5 {
		t.Errorf("expected RateLimitMaxAttempts default 5, got %d", cfg.RateLimitMaxAttempts)
	}
	if cfg.RateLimitWindowSeconds != 900 {
		t.Errorf("expected RateLimitWindowSeconds default 900, got %d", cfg.RateLimitWindowSeconds)
	}
	expectedSchedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	if len(cfg.RateLimitBackoffSchedule) != len(expectedSchedule) {
		t.Fatalf("expected schedule length %d, got %d", len(expectedSchedule), len(cfg.RateLimitBackoffSchedule))
	}
	for i, d := range expectedSchedule {
		if cfg.RateLimitBackoffSchedule[i] != d {
			t.Errorf("expected schedule[%d] = %v, got %v", i, d, cfg.RateLimitBackoffSchedule[i])
		}
	}
	if cfg.RateLimitViolationResetDays != 7 {
		t.Errorf("expected RateLimitViolationResetDays default 7, got %d", cfg.RateLimitViolationResetDays)
	}
}

// TestConfig_CookieSecure locks in the audit H4 contract: refresh-token cookies
// carry Secure on every TLS origin, and only plaintext dev opts out. Both
// directions matter — a false negative ships 30-day refresh tokens in cleartext,
// a false positive silently breaks local development.
func TestConfig_CookieSecure(t *testing.T) {
	cases := []struct {
		name       string
		appBaseURL string
		want       bool
	}{
		{name: "https production domain", appBaseURL: "https://auth.acme.com", want: true},
		{name: "https with trailing slash", appBaseURL: "https://auth.acme.com/", want: true},
		{name: "https with port", appBaseURL: "https://localhost:8443", want: true},
		{name: "uppercase scheme", appBaseURL: "HTTPS://AUTH.ACME.COM", want: true},
		{name: "surrounding whitespace", appBaseURL: "  https://auth.acme.com  ", want: true},
		{name: "http localhost dev", appBaseURL: "http://localhost:8080", want: false},
		{name: "http lan host", appBaseURL: "http://192.168.1.20:8080", want: false},
		{name: "empty falls back to insecure", appBaseURL: "", want: false},
		// Guards against a naive strings.Contains("https") check.
		{name: "http host merely containing https", appBaseURL: "http://https.example.com", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &EnvConfig{AppBaseURL: tc.appBaseURL}
			if got := cfg.CookieSecure(); got != tc.want {
				t.Errorf("CookieSecure() with AppBaseURL=%q = %v, want %v", tc.appBaseURL, got, tc.want)
			}
		})
	}
}
