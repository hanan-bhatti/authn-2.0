/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/config/validate.go
 * Tier: Configuration Layer
 *
 * Cross-field configuration rules.
 *
 * env.go checks each variable in isolation ("is this a number?"). The checks
 * here are the ones that need more than one value to decide: a setting that is
 * fine alone but dangerous alongside another, or required only because some
 * other switch is on.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// minSecretLength is the shortest accepted cryptographic secret. AES-256 needs
// 32 bytes of key material, so anything shorter cannot supply full strength.
const minSecretLength = 32

// maxOAuthCodeTTL is the longest authorization-code lifetime RFC 6749 section
// 4.1.2 recommends. Codes are single-use and redeemed immediately, so a long
// window only widens the replay opportunity if one leaks.
const maxOAuthCodeTTL = 10 * time.Minute

// Validate checks rules that span more than one setting.
//
// Returns nil when the configuration is safe to run. Returns an error listing
// every violation when it is not; the caller should exit rather than start.
func (c *Config) Validate() error {
	var problems []string

	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	c.validateCORS(add)
	c.validateWebAuthn(add)
	c.validateDelivery(add)
	c.validateProduction(add)
	c.validateLifetimes(add)
	c.validatePlatformTenant(add)

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

// validateCORS rejects the origin-reflection-with-credentials combination.
//
// A wildcard origin is harmless on a public, credential-free API. Combined with
// credentials it is a serious hole: the browser sends the user's cookies on
// cross-origin requests and hands the response back to the calling page, so any
// site a signed-in user visits can act as them and read the result. Browsers
// reject a literal "*" alongside credentials, but a server that reflects
// whatever Origin it receives defeats that protection.
func (c *Config) validateCORS(add func(string, ...any)) {
	if len(c.CORSAllowedOrigins) == 0 {
		add("CORS_ALLOWED_ORIGINS must list at least one origin")
		return
	}

	for _, origin := range c.CORSAllowedOrigins {
		if origin != "*" {
			continue
		}
		if c.CORSAllowCredentials {
			add("CORS_ALLOWED_ORIGINS cannot be \"*\" while CORS_ALLOW_CREDENTIALS is true: " +
				"that lets any website make authenticated requests with the user's cookies. " +
				"List the exact origins that need access, or set CORS_ALLOW_CREDENTIALS=false")
		}
		if c.IsProduction() {
			add("CORS_ALLOWED_ORIGINS cannot be \"*\" in production")
		}
	}
}

// validateWebAuthn checks that every passkey origin resolves to the configured
// relying-party domain.
//
// The browser compares a ceremony's origin against the relying-party ID and
// aborts on a mismatch, so an inconsistent pair here surfaces as passkey
// enrolment failing in the browser with no server-side error to point at.
func (c *Config) validateWebAuthn(add func(string, ...any)) {
	if c.WebAuthnRPID == "" {
		add("WEBAUTHN_RP_ID must be set to the domain passkeys are bound to")
		return
	}
	if strings.Contains(c.WebAuthnRPID, "://") || strings.Contains(c.WebAuthnRPID, ":") {
		add("WEBAUTHN_RP_ID must be a bare domain without scheme or port, got %q", c.WebAuthnRPID)
		return
	}

	for _, origin := range c.WebAuthnRPOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" {
			add("WEBAUTHN_RP_ORIGINS entry %q is not a valid origin", origin)
			continue
		}
		host := parsed.Hostname()
		if host != c.WebAuthnRPID && !strings.HasSuffix(host, "."+c.WebAuthnRPID) {
			add("WEBAUTHN_RP_ORIGINS entry %q does not belong to WEBAUTHN_RP_ID %q",
				origin, c.WebAuthnRPID)
		}
	}
}

// validateDelivery checks that a selected email or SMS provider has the
// credentials it needs. Catching this at startup avoids the failure mode where
// sign-up works but the verification mail silently never sends.
func (c *Config) validateDelivery(add func(string, ...any)) {
	switch c.EmailDriver {
	case "resend":
		if c.ResendAPIKey == "" {
			add("RESEND_API_KEY is required when EMAIL_DRIVER=resend")
		}
	case "sendgrid":
		if c.SendGridAPIKey == "" {
			add("SENDGRID_API_KEY is required when EMAIL_DRIVER=sendgrid")
		}
	case "postmark":
		if c.PostmarkServerToken == "" {
			add("POSTMARK_SERVER_TOKEN is required when EMAIL_DRIVER=postmark")
		}
	case "aws_ses":
		if c.AWSAccessKeyID == "" || c.AWSSecretAccessKey == "" {
			add("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required when EMAIL_DRIVER=aws_ses")
		}
	case "smtp":
		if c.SMTPHost == "" {
			add("SMTP_HOST is required when EMAIL_DRIVER=smtp")
		}
	}

	switch c.SMSDriver {
	case "twilio":
		if c.TwilioAccountSID == "" || c.TwilioAuthToken == "" || c.TwilioFromNumber == "" {
			add("TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER are required when SMS_DRIVER=twilio")
		}
	case "messagebird":
		if c.MessageBirdAccessKey == "" {
			add("MESSAGEBIRD_ACCESS_KEY is required when SMS_DRIVER=messagebird")
		}
	}
}

// validateProduction enforces the settings that only matter once real users are
// involved. Each of these is a safe convenience in development and a defect in
// production.
func (c *Config) validateProduction(add func(string, ...any)) {
	if !c.IsProduction() {
		// Secrets are optional in development, but a short one is always a
		// mistake worth reporting rather than a weaker key applied silently.
		if c.EncryptionKey != "" && len(c.EncryptionKey) < minSecretLength {
			add("AUTHN_ENCRYPTION_KEY must be at least %d characters, got %d",
				minSecretLength, len(c.EncryptionKey))
		}
		if c.APIKeyPepper != "" && len(c.APIKeyPepper) < minSecretLength {
			add("AUTHN_API_KEY_PEPPER must be at least %d characters, got %d",
				minSecretLength, len(c.APIKeyPepper))
		}
		return
	}

	if !strings.HasPrefix(strings.ToLower(c.AppBaseURL), "https://") {
		add("APP_BASE_URL must use https:// in production, got %q — "+
			"session cookies are marked Secure based on this value", c.AppBaseURL)
	}
	if !strings.HasPrefix(strings.ToLower(c.Issuer), "https://") {
		add("ISSUER_URL must use https:// in production, got %q", c.Issuer)
	}
	if c.WebAuthnRPID == "localhost" {
		add("WEBAUTHN_RP_ID is still \"localhost\" in production")
	}
	if c.EncryptionKey == c.APIKeyPepper && c.EncryptionKey != "" {
		add("AUTHN_ENCRYPTION_KEY and AUTHN_API_KEY_PEPPER must be different values")
	}
	if c.DatabaseAutoMigrate {
		add("DATABASE_AUTO_MIGRATE should be false in production: run migrations " +
			"as a reviewed deployment step so schema changes are not applied by " +
			"whichever instance happens to boot first")
	}
}

// validateLifetimes checks token lifetimes against each other.
func (c *Config) validateLifetimes(add func(string, ...any)) {
	if c.AccessTokenTTL >= c.RefreshTokenTTL {
		add("ACCESS_TOKEN_TTL (%s) must be shorter than REFRESH_TOKEN_TTL (%s): "+
			"the refresh token exists to outlive the access token",
			c.AccessTokenTTL, c.RefreshTokenTTL)
	}
	if c.SessionGracePeriod >= c.AccessTokenTTL {
		add("SESSION_GRACE_PERIOD (%s) must be much shorter than ACCESS_TOKEN_TTL (%s): "+
			"it only covers requests already in flight during a token rotation",
			c.SessionGracePeriod, c.AccessTokenTTL)
	}
	// RFC 6749 section 4.1.2 recommends a maximum authorization-code lifetime
	// of ten minutes, since codes are single-use and redeemed immediately.
	if c.OAuthCodeTTL > maxOAuthCodeTTL {
		add("OAUTH_CODE_TTL (%s) exceeds the %s maximum recommended by RFC 6749",
			c.OAuthCodeTTL, maxOAuthCodeTTL)
	}
}

// validatePlatformTenant checks the hosted control plane's configuration.
//
// The two settings are all-or-nothing. An ID without a slug would leave the
// slug unreserved, so a customer could provision a tenant claiming it — and
// because provisioning is idempotent by slug, that caller would be handed the
// control-plane tenant instead of a new one. A slug without an ID is a
// half-finished configuration that silently leaves the platform routes disabled.
func (c *Config) validatePlatformTenant(add func(string, ...any)) {
	id := strings.TrimSpace(c.PlatformTenantID)
	slug := strings.TrimSpace(c.PlatformTenantSlug)

	if id == "" && slug == "" {
		return // no control plane on this deployment; the platform routes 404
	}

	if id == "" || slug == "" {
		add("PLATFORM_TENANT_ID and PLATFORM_TENANT_SLUG must be set together: " +
			"the slug is what stops a customer provisioning over the control plane")
		return
	}

	if !strings.HasPrefix(id, "tnt_") {
		add("PLATFORM_TENANT_ID (%q) must be a tenant identifier beginning with \"tnt_\"", id)
	}

	// tnt_default is the development seeder's tenant, which ships with published
	// demo credentials. Pointing the control plane at it would put those
	// credentials in front of the tenant-provisioning API.
	if id == "tnt_default" {
		add("PLATFORM_TENANT_ID must not be \"tnt_default\": that tenant is created by " +
			"the development seeder with credentials published in source control")
	}
}
