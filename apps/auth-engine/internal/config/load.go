/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/config/load.go
 * Tier: Configuration Layer
 *
 * Reads the environment into a Config and refuses to return one that would be
 * unsafe to run.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package config

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// dotEnvFilename is the conventional name of the local environment file.
const dotEnvFilename = ".env"

// dotEnvSearchDepth is how many parent directories are searched for a .env
// file. Four levels reaches the repository root from a package directory in a
// monorepo layout without wandering into unrelated parts of the filesystem.
const dotEnvSearchDepth = 4

// Load reads configuration from the environment and validates it.
//
// A local .env file, if present, fills in variables that are not already set.
// Real environment variables always win, so a container's injected settings are
// never overridden by a file left in the image.
//
// Returns the populated Config on success. Returns an error listing every
// problem found when any variable is missing, malformed or unsafe for the
// selected environment — the caller should treat that as fatal and exit.
func Load() (*Config, error) {
	loadDotEnv()

	r := &envReader{}

	// The environment tier is read first: it decides how strict the rest of
	// the loading is, and which defaults apply.
	env := r.oneOf("APP_ENV", EnvDevelopment, EnvDevelopment, EnvTest, EnvProduction)
	production := env == EnvProduction

	cfg := &Config{
		Env:               env,
		Host:              r.str("HOST", "0.0.0.0"),
		Port:              r.port("PORT", 8080),
		ReadTimeout:       r.duration("SERVER_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      r.duration("SERVER_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:       r.duration("SERVER_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout:   r.duration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
		BodyLimit:         r.positive("SERVER_BODY_LIMIT_BYTES", 4*1024*1024),
		TrustProxyHeaders: r.boolean("SERVER_TRUST_PROXY_HEADERS", false),

		AppName:    r.str("AUTHN_APP_NAME", "Authn Platform"),
		AppVersion: r.str("AUTHN_APP_VERSION", "0.1.0"),

		AppBaseURL: r.absoluteURL("APP_BASE_URL", "http://localhost:8080"),
		Issuer:     r.absoluteURL("ISSUER_URL", "http://localhost:8080"),

		CORSAllowedOrigins:   r.originList("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
		CORSAllowedMethods:   r.list("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
		CORSAllowedHeaders:   r.list("CORS_ALLOWED_HEADERS", defaultCORSHeaders()),
		CORSAllowCredentials: r.boolean("CORS_ALLOW_CREDENTIALS", true),
		CORSMaxAge:           r.duration("CORS_MAX_AGE", 12*time.Hour),

		DatabaseMaxOpenConns:    r.positive("DATABASE_MAX_OPEN_CONNS", 25),
		DatabaseMaxIdleConns:    r.positive("DATABASE_MAX_IDLE_CONNS", 5),
		DatabaseConnMaxLifetime: r.duration("DATABASE_CONN_MAX_LIFETIME", 30*time.Minute),
		DatabaseAutoMigrate:     r.boolean("DATABASE_AUTO_MIGRATE", !production),

		RedisRequired: r.boolean("REDIS_REQUIRED", production),

		JWTKeyID:          r.str("JWT_KEY_ID", "key_v1"),
		JWTSigningKeyPath: r.str("JWT_SIGNING_KEY_PATH", ".keys/rsa_private.pem"),

		AccessTokenTTL:       r.duration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:      r.duration("REFRESH_TOKEN_TTL", 720*time.Hour),
		SessionGracePeriod:   r.duration("SESSION_GRACE_PERIOD", 10*time.Second),
		EmailVerificationTTL: r.duration("EMAIL_VERIFICATION_TTL", 24*time.Hour),
		MagicLinkTTL:         r.duration("MAGIC_LINK_TTL", 15*time.Minute),
		MFAChallengeTTL:      r.duration("MFA_CHALLENGE_TTL", 5*time.Minute),
		SocialAuthStateTTL:   r.duration("SOCIAL_AUTH_STATE_TTL", 10*time.Minute),
		OAuthCodeTTL:         r.duration("OAUTH_CODE_TTL", 10*time.Minute),
		IDTokenTTL:           r.duration("ID_TOKEN_TTL", time.Hour),
		RecoveryTokenTTL:     r.duration("RECOVERY_TOKEN_TTL", time.Hour),
		InvitationTTL:        r.duration("INVITATION_TTL", 168*time.Hour),

		RateLimitEnabled:            r.boolean("RATELIMIT_ENABLED", true),
		RateLimitMaxAttempts:        r.positive("RATELIMIT_MAX_ATTEMPTS", 5),
		RateLimitWindow:             r.duration("RATELIMIT_WINDOW", 15*time.Minute),
		RateLimitIPBudgetMultiplier: r.positive("RATELIMIT_IP_BUDGET_MULTIPLIER", 10),
		RateLimitBackoffSchedule:    r.durationList("RATELIMIT_BACKOFF_SCHEDULE", defaultBackoffSchedule()),
		RateLimitViolationResetDays: r.positive("RATELIMIT_VIOLATION_RESET_DAYS", 7),
		RateLimitFailClosed:         r.boolean("RATELIMIT_FAIL_CLOSED", production),

		ResendRateLimitEnabled:     r.boolean("RESEND_RATELIMIT_ENABLED", true),
		ResendRateLimitMaxAttempts: r.positive("RESEND_RATELIMIT_MAX_ATTEMPTS", 3),
		ResendRateLimitWindow:      r.duration("RESEND_RATELIMIT_WINDOW", time.Hour),

		EmailDriver:      r.oneOf("EMAIL_DRIVER", "noop", "smtp", "resend", "sendgrid", "postmark", "aws_ses", "noop"),
		EmailFromAddress: r.str("EMAIL_FROM_ADDRESS", "noreply@authn.local"),
		EmailFromName:    r.str("EMAIL_FROM_NAME", "Authn"),

		SMTPHost:     r.str("SMTP_HOST", "localhost"),
		SMTPPort:     r.port("SMTP_PORT", 1025),
		SMTPUser:     r.str("SMTP_USER", ""),
		SMTPPassword: r.str("SMTP_PASSWORD", ""),

		ResendAPIKey:        r.str("RESEND_API_KEY", ""),
		SendGridAPIKey:      r.str("SENDGRID_API_KEY", ""),
		PostmarkServerToken: r.str("POSTMARK_SERVER_TOKEN", ""),

		AWSAccessKeyID:     r.str("AWS_ACCESS_KEY_ID", ""),
		AWSSecretAccessKey: r.str("AWS_SECRET_ACCESS_KEY", ""),
		AWSRegion:          r.str("AWS_REGION", "us-east-1"),

		SMSDriver:        r.oneOf("SMS_DRIVER", "noop", "twilio", "messagebird", "aws_sns", "noop"),
		TwilioAccountSID: r.str("TWILIO_ACCOUNT_SID", ""),
		TwilioAuthToken:  r.str("TWILIO_AUTH_TOKEN", ""),
		TwilioFromNumber: r.str("TWILIO_FROM_NUMBER", ""),

		MessageBirdAccessKey:  r.str("MESSAGEBIRD_ACCESS_KEY", ""),
		MessageBirdOriginator: r.str("MESSAGEBIRD_ORIGINATOR", "Authn"),

		WebAuthnRPID:          r.str("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnRPOrigins:     r.originList("WEBAUTHN_RP_ORIGINS", []string{"http://localhost:8080", "http://localhost:3000"}),
		WebAuthnRPDisplayName: r.str("WEBAUTHN_RP_DISPLAY_NAME", "Authn Platform"),

		SAMLSPEntityIDPrefix:      r.str("SAML_SP_ENTITY_ID_PREFIX", "https://authn.com/saml/sp/"),
		SAMLAssertionConsumerPath: r.str("SAML_ACS_PATH", "/v1/saml/acs"),

		WebhookWorkerCount:        r.positive("WEBHOOK_WORKER_COUNT", 5),
		DegradedModeCheckInterval: r.duration("DEGRADED_MODE_CHECK_INTERVAL", time.Second),

		OrgMetadataMaxBytes: r.positive("ORG_METADATA_MAX_BYTES", 10*1024),

		FeaturePush2FAEnabled:       r.boolean("FEATURE_PUSH_2FA_ENABLED", true),
		FeatureMagicLinkEnabled:     r.boolean("FEATURE_MAGIC_LINK_ENABLED", true),
		FeatureWebhooksEnabled:      r.boolean("FEATURE_WEBHOOKS_ENABLED", true),
		FeatureRBACEnabled:          r.boolean("FEATURE_RBAC_ENABLED", true),
		FeatureImpersonationEnabled: r.boolean("FEATURE_IMPERSONATION_ENABLED", true),
	}

	// Infrastructure endpoints and secrets have no safe fallback in production.
	// Development gets defaults that work against a local stack so a fresh
	// clone runs without setup.
	if production {
		cfg.DatabaseURL = r.required("DATABASE_URL")
		cfg.RedisURL = r.required("REDIS_URL")
		cfg.EncryptionKey = r.requiredMinLen("AUTHN_ENCRYPTION_KEY", minSecretLength)
		cfg.APIKeyPepper = r.requiredMinLen("AUTHN_API_KEY_PEPPER", minSecretLength)
	} else {
		cfg.DatabaseURL = r.str("DATABASE_URL", "sqlite://file:authn.db?_fk=1&cache=shared")
		cfg.RedisURL = r.str("REDIS_URL", "redis://localhost:6379")
		cfg.EncryptionKey = r.str("AUTHN_ENCRYPTION_KEY", "")
		cfg.APIKeyPepper = r.str("AUTHN_API_KEY_PEPPER", "")
	}

	// Both are empty on a self-hosted deployment, which disables the hosted
	// control plane rather than defaulting it to some tenant.
	cfg.PlatformTenantID = r.str("PLATFORM_TENANT_ID", "")
	cfg.PlatformTenantSlug = r.str("PLATFORM_TENANT_SLUG", "")

	if err := r.err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultCORSHeaders lists the request headers the engine's own clients send.
// Anything not listed here is rejected by the browser during preflight.
func defaultCORSHeaders() []string {
	return []string{
		"Origin",
		"Content-Type",
		"Accept",
		"Authorization",
		"X-Authn-Publishable-Key",
		"X-Authn-Secret-Key",
		"X-Authn-Api-Key",
		"X-Authn-Tenant-Id",
		"X-Authn-Environment",
	}
}

// defaultBackoffSchedule is the escalating lockout applied to an identity that
// keeps failing: each repeat offence moves one step down the list.
func defaultBackoffSchedule() []time.Duration {
	return []time.Duration{
		15 * time.Minute,
		time.Hour,
		6 * time.Hour,
		24 * time.Hour,
	}
}

// loadDotEnv populates unset environment variables from the nearest .env file.
//
// The search walks upward from the working directory so the server can be
// started from the module directory or the repository root. Variables already
// present in the real environment are left untouched, which keeps container and
// CI settings authoritative over any file baked into an image.
//
// A missing .env file is not an error: production deployments inject variables
// directly and have no such file.
func loadDotEnv() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}

	for depth := 0; depth <= dotEnvSearchDepth; depth++ {
		path := filepath.Join(dir, dotEnvFilename)
		if data, err := os.ReadFile(path); err == nil {
			applyDotEnv(string(data))
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return // reached the filesystem root
		}
		dir = parent
	}
}

// applyDotEnv parses KEY=VALUE lines and sets any variable not already defined.
// Blank lines and # comments are skipped, an optional "export " prefix is
// tolerated, and surrounding quotes are stripped.
func applyDotEnv(contents string) {
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		// Strip a trailing comment, but only outside quotes so that a value
		// such as a password containing '#' survives intact.
		if !strings.HasPrefix(value, `"`) && !strings.HasPrefix(value, `'`) {
			if idx := strings.Index(value, " #"); idx != -1 {
				value = strings.TrimSpace(value[:idx])
			}
		}
		value = strings.Trim(value, `"'`)

		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
}
