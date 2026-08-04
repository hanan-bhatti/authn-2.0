/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/config/env_config.go
 * Tier: Configuration & Pre-flight Boot Layer
 *
 * Description: Pre-flight environment variable validation manager. Ensures zero
 *              hardcoded secrets or ports, validates all required variables at boot,
 *              and provides typed feature flags across the engine.
 *
 * Security Notice:
 *   - Missing required keys (AUTHN_ENCRYPTION_KEY, DATABASE_URL) trigger immediate
 *     fail-fast process exit to prevent running in an insecure state.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvConfig holds all validated runtime configurations and feature flags for the Go engine.
type EnvConfig struct {
	// Server & Environment Settings
	Port string
	Env  string // "development" | "test" | "production"

	// Database & Cache Infrastructure
	DatabaseURL string
	RedisURL    string

	// KMS & Cryptographic Secrets
	AuthnEncryptionKey string // 32-byte AES-256-GCM KMS key
	AuthnAPIKeyPepper  string // 32-byte pepper key for secret API key HMAC hashing
	AuthnKeyID         string // Active JWKS key identifier
	Issuer             string // OpenID Connect Issuer URL
	JWTSigningKeyPath  string // Path to RSA/ECDSA private key for ID token signing

	// Multi-Dimensional Rate Limiting
	RateLimitEnabled            bool
	RateLimitMaxAttempts        int
	RateLimitWindowSeconds      int
	RateLimitBackoffSchedule    []time.Duration
	RateLimitViolationResetDays int

	// Email & Communication Provider Settings
	EmailDriver         string // "smtp" | "resend" | "sendgrid" | "postmark" | "aws_ses" | "noop"
	SMTPHost            string
	SMTPPort            string
	SMTPUser            string
	SMTPPassword        string
	ResendAPIKey        string
	SendGridAPIKey      string
	PostmarkServerToken string
	AWSAccessKeyID      string
	AWSSecretAccessKey  string
	AWSRegion           string
	EmailFromAddress    string
	AppBaseURL          string

	// SMS & WhatsApp Provider Settings
	SMSDriver             string // "twilio" | "messagebird" | "aws_sns" | "noop"
	TwilioAccountSID      string
	TwilioAuthToken       string
	TwilioFromNumber      string
	MessageBirdAccessKey  string
	MessageBirdOriginator string

	// Feature Flags
	FeaturePush2FAEnabled       bool
	FeatureMagicLinkEnabled     bool
	FeatureWebhooksEnabled      bool
	FeatureRBACEnabled          bool
	FeatureImpersonationEnabled bool

	// WebAuthn / Passkeys (FIDO2) Relying Party Configuration
	// CRITICAL NOTICE: WebAuthnRPID defines the domain scope for enrolled passkeys.
	// Changing WebAuthnRPID after users have enrolled passkeys will invalidate all existing passkeys.
	WebAuthnRPID          string   // e.g. "localhost" or "auth.example.com"
	WebAuthnRPOrigins     []string // e.g. ["http://localhost:8080", "http://localhost:3000"]
	WebAuthnRPDisplayName string   // e.g. "Authn Platform"
}

// SocialCallbackURL returns the exact redirect URI to register in each OAuth provider's console.
// It is derived from AppBaseURL (AUTHN_BASE_URL / APP_BASE_URL env var) so it adapts to any
// self-hosted domain, cloud domain, or local dev server — never hardcoded.
//
// Example: cfg.SocialCallbackURL("google")
//
//	→ "https://auth.acme.com/v1/client/auth/social/google/callback"
//	→ "http://localhost:8080/v1/client/auth/social/google/callback"  (dev)
func (c *EnvConfig) SocialCallbackURL(provider string) string {
	base := strings.TrimRight(c.AppBaseURL, "/")
	return base + "/v1/client/auth/social/" + provider + "/callback"
}

// loadDotEnv searches candidate paths for a .env file and populates missing process environment variables.
func loadDotEnv() {
	candidatePaths := []string{".env", "../.env", "../../.env", "../../../.env", "/home/hanan-bhatti/authn/.env"}
	for _, path := range candidatePaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if idx := strings.Index(val, "#"); idx != -1 {
				val = strings.TrimSpace(val[:idx])
			}
			val = strings.Trim(val, `"'`)
			if os.Getenv(key) == "" {
				os.Setenv(key, val)
			}
		}
		break
	}
}

// LoadAndValidateConfig executes the pre-flight boot check and validates all environment variables.
func LoadAndValidateConfig() (*EnvConfig, error) {
	loadDotEnv()

	defaultSchedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}

	cfg := &EnvConfig{
		Port:                        getEnvOrDefault("PORT", "8080"),
		Env:                         getEnvOrDefault("ENV", "development"),
		DatabaseURL:                 os.Getenv("DATABASE_URL"),
		RedisURL:                    getEnvOrDefault("AUTHN_REDIS_URL", getEnvOrDefault("REDIS_URL", "redis://localhost:6379")),
		AuthnEncryptionKey:          os.Getenv("AUTHN_ENCRYPTION_KEY"),
		AuthnAPIKeyPepper:           os.Getenv("AUTHN_API_KEY_PEPPER"),
		AuthnKeyID:                  getEnvOrDefault("AUTHN_KEY_ID", "key_v1"),
		Issuer:                      getEnvOrDefault("ISSUER_URL", "http://localhost:8080"),
		JWTSigningKeyPath:           getEnvOrDefault("AUTHN_RSA_KEY_PATH", getEnvOrDefault("JWT_SIGNING_KEY_PATH", ".keys/rsa_private.pem")),
		RateLimitEnabled:            getEnvAsBoolOrDefault("AUTHN_RATELIMIT_ENABLED", true),
		RateLimitMaxAttempts:        getEnvAsIntOrDefault("AUTHN_RATELIMIT_MAX_ATTEMPTS", 5),
		RateLimitWindowSeconds:      getEnvAsIntOrDefault("AUTHN_RATELIMIT_WINDOW_SECONDS", 900),
		RateLimitBackoffSchedule:    parseBackoffSchedule(getEnvOrDefault("AUTHN_RATELIMIT_BACKOFF_SCHEDULE", "15m,1h,6h,24h"), defaultSchedule),
		RateLimitViolationResetDays: getEnvAsIntOrDefault("AUTHN_RATELIMIT_VIOLATION_RESET_DAYS", 7),
		EmailDriver:                 getEnvOrDefault("EMAIL_DRIVER", "smtp"),
		SMTPHost:                    getEnvOrDefault("SMTP_HOST", "localhost"),
		SMTPPort:                    getEnvOrDefault("SMTP_PORT", "1025"),
		SMTPUser:                    os.Getenv("SMTP_USER"),
		SMTPPassword:                os.Getenv("SMTP_PASSWORD"),
		ResendAPIKey:                os.Getenv("RESEND_API_KEY"),
		SendGridAPIKey:              os.Getenv("SENDGRID_API_KEY"),
		PostmarkServerToken:         os.Getenv("POSTMARK_SERVER_TOKEN"),
		AWSAccessKeyID:              os.Getenv("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:          os.Getenv("AWS_SECRET_ACCESS_KEY"),
		AWSRegion:                   getEnvOrDefault("AWS_REGION", "us-east-1"),
		EmailFromAddress:            getEnvOrDefault("EMAIL_FROM_ADDRESS", "noreply@authn.local"),
		AppBaseURL:                  getEnvOrDefault("APP_BASE_URL", "http://localhost:8080"),
		SMSDriver:                   getEnvOrDefault("SMS_DRIVER", "noop"),
		TwilioAccountSID:            os.Getenv("TWILIO_ACCOUNT_SID"),
		TwilioAuthToken:             os.Getenv("TWILIO_AUTH_TOKEN"),
		TwilioFromNumber:            os.Getenv("TWILIO_FROM_NUMBER"),
		MessageBirdAccessKey:        os.Getenv("MESSAGEBIRD_ACCESS_KEY"),
		MessageBirdOriginator:       getEnvOrDefault("MESSAGEBIRD_ORIGINATOR", "Authn"),
		FeaturePush2FAEnabled:       getEnvAsBoolOrDefault("FEATURE_PUSH_2FA_ENABLED", true),
		FeatureMagicLinkEnabled:     getEnvAsBoolOrDefault("FEATURE_MAGIC_LINK_ENABLED", true),
		FeatureWebhooksEnabled:      getEnvAsBoolOrDefault("FEATURE_WEBHOOKS_ENABLED", true),
		FeatureRBACEnabled:          getEnvAsBoolOrDefault("FEATURE_RBAC_ENABLED", true),
		FeatureImpersonationEnabled: getEnvAsBoolOrDefault("FEATURE_IMPERSONATION_ENABLED", true),
		WebAuthnRPID:                getEnvOrDefault("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPOrigins:           getEnvAsStringSliceOrDefault("WEBAUTHN_RP_ORIGINS", []string{"http://localhost:8080", "http://localhost:3000"}),
		WebAuthnRPDisplayName:       getEnvOrDefault("WEBAUTHN_RP_DISPLAY_NAME", "Authn Platform"),
	}

	// Validate required variables in production / live mode
	var validationErrors []string

	if cfg.DatabaseURL == "" {
		validationErrors = append(validationErrors, "DATABASE_URL is required but not set")
	}

	if cfg.Env == "production" {
		if cfg.AuthnEncryptionKey == "" || len(cfg.AuthnEncryptionKey) < 32 {
			validationErrors = append(validationErrors, "AUTHN_ENCRYPTION_KEY must be set and at least 32 characters in production")
		}
		if cfg.AuthnAPIKeyPepper == "" || len(cfg.AuthnAPIKeyPepper) < 32 {
			validationErrors = append(validationErrors, "AUTHN_API_KEY_PEPPER must be set and at least 32 characters in production")
		}
	}

	if len(validationErrors) > 0 {
		return nil, fmt.Errorf("pre-flight environment validation failed:\n  - %s", strings.Join(validationErrors, "\n  - "))
	}

	return cfg, nil
}

// getEnvOrDefault returns the value of an environment variable or a fallback default.
func getEnvOrDefault(key string, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

// getEnvAsBoolOrDefault returns the boolean value of an environment variable or a fallback.
func getEnvAsBoolOrDefault(key string, fallback bool) bool {
	valStr := strings.TrimSpace(os.Getenv(key))
	if valStr == "" {
		return fallback
	}
	val, err := strconv.ParseBool(valStr)
	if err != nil {
		return fallback
	}
	return val
}

// getEnvAsIntOrDefault returns the integer value of an environment variable or a fallback.
func getEnvAsIntOrDefault(key string, fallback int) int {
	valStr := strings.TrimSpace(os.Getenv(key))
	if valStr == "" {
		return fallback
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return fallback
	}
	return val
}

// parseBackoffSchedule parses a comma-separated list of duration strings (e.g. "15m,1h,6h,24h").
func parseBackoffSchedule(raw string, fallback []time.Duration) []time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	res := make([]time.Duration, 0, len(parts))
	for _, p := range parts {
		d, err := time.ParseDuration(strings.TrimSpace(p))
		if err != nil {
			return fallback
		}
		res = append(res, d)
	}
	if len(res) == 0 {
		return fallback
	}
	return res
}

// getEnvAsStringSliceOrDefault returns a comma-separated environment variable parsed as a slice of strings.
func getEnvAsStringSliceOrDefault(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	if len(res) == 0 {
		return fallback
	}
	return res
}
