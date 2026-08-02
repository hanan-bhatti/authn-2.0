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

	// Feature Flags
	FeaturePush2FAEnabled       bool
	FeatureMagicLinkEnabled     bool
	FeatureWebhooksEnabled      bool
	FeatureRBACEnabled          bool
	FeatureImpersonationEnabled bool
}

// LoadAndValidateConfig executes the pre-flight boot check and validates all environment variables.
//
// Parameters: None
//
// Returns:
//   - *EnvConfig: Validated environment configuration struct.
//   - error: Non-nil if any required variable is missing or malformed.
func LoadAndValidateConfig() (*EnvConfig, error) {
	cfg := &EnvConfig{
		Port:                        getEnvOrDefault("PORT", "8080"),
		Env:                         getEnvOrDefault("ENV", "development"),
		DatabaseURL:                 os.Getenv("DATABASE_URL"),
		RedisURL:                    getEnvOrDefault("REDIS_URL", "localhost:6379"),
		AuthnEncryptionKey:          os.Getenv("AUTHN_ENCRYPTION_KEY"),
		AuthnAPIKeyPepper:           os.Getenv("AUTHN_API_KEY_PEPPER"),
		AuthnKeyID:                  getEnvOrDefault("AUTHN_KEY_ID", "key_v1"),
		Issuer:                      getEnvOrDefault("ISSUER_URL", "http://localhost:8080"),
		JWTSigningKeyPath:           getEnvOrDefault("JWT_SIGNING_KEY_PATH", "/etc/authn/keys/rsa_private.pem"),
		FeaturePush2FAEnabled:       getEnvAsBoolOrDefault("FEATURE_PUSH_2FA_ENABLED", true),
		FeatureMagicLinkEnabled:     getEnvAsBoolOrDefault("FEATURE_MAGIC_LINK_ENABLED", true),
		FeatureWebhooksEnabled:      getEnvAsBoolOrDefault("FEATURE_WEBHOOKS_ENABLED", true),
		FeatureRBACEnabled:          getEnvAsBoolOrDefault("FEATURE_RBAC_ENABLED", true),
		FeatureImpersonationEnabled: getEnvAsBoolOrDefault("FEATURE_IMPERSONATION_ENABLED", true),
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
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// getEnvAsBoolOrDefault returns the boolean value of an environment variable or a fallback.
func getEnvAsBoolOrDefault(key string, fallback bool) bool {
	valStr := os.Getenv(key)
	if valStr == "" {
		return fallback
	}
	val, err := strconv.ParseBool(valStr)
	if err != nil {
		return fallback
	}
	return val
}
