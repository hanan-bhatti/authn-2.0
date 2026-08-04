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
