/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/config/config.go
 * Tier: Configuration Layer
 *
 * Every runtime setting the engine reads, loaded from the environment once at
 * startup and validated before the server accepts traffic.
 *
 * Two rules govern this package:
 *
 *  1. Nothing that varies between deployments is written in Go source. Ports,
 *     URLs, origins, token lifetimes and credentials all arrive as environment
 *     variables, so the same binary runs unmodified in development, staging and
 *     production.
 *
 *  2. Configuration fails at startup, never mid-request. A malformed value stops
 *     the process with a message naming the variable. A server that boots with a
 *     silently-defaulted security setting is worse than one that refuses to boot.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package config

import (
	"strings"
	"time"
)

// Environment names the deployment tier. It controls which defaults apply and
// how strict validation is: production demands explicit values for anything
// security-critical, while development supplies workable defaults so a fresh
// clone starts with no setup.
const (
	EnvDevelopment = "development"
	EnvTest        = "test"
	EnvProduction  = "production"
)

// Config holds every validated runtime setting. It is built once by Load and
// treated as read-only afterwards, so it is safe to share across goroutines
// without locking.
type Config struct {
	// ---------------------------------------------------------------------
	// Server
	// ---------------------------------------------------------------------

	// Env is the deployment tier: development, test or production.
	Env string
	// Host is the network interface to bind. "0.0.0.0" accepts connections from
	// anywhere; "127.0.0.1" restricts to the local machine.
	Host string
	// Port is the TCP port to listen on.
	Port int
	// ReadTimeout caps how long reading a request may take. It bounds slow-read
	// attacks that hold connections open by sending bytes very slowly.
	ReadTimeout time.Duration
	// WriteTimeout caps how long writing a response may take.
	WriteTimeout time.Duration
	// IdleTimeout closes keep-alive connections that go quiet, freeing sockets.
	IdleTimeout time.Duration
	// ShutdownTimeout is how long in-flight requests get to finish after a
	// termination signal before the process exits.
	ShutdownTimeout time.Duration
	// BodyLimit is the largest accepted request body, in bytes.
	BodyLimit int
	// TrustProxyHeaders makes the server read the client IP from the
	// X-Forwarded-For header instead of the socket's peer address.
	//
	// Enable only when a proxy you control sets that header, because a client
	// can forge it. With this on behind no proxy, an attacker spoofs a new IP
	// per request and escapes every per-IP rate limit.
	TrustProxyHeaders bool

	// ---------------------------------------------------------------------
	// Public identity
	// ---------------------------------------------------------------------

	// AppName is the product name shown to users: in outbound mail, and as the
	// issuer label in an authenticator app.
	//
	// Changing it after users have enrolled TOTP is cosmetic but confusing —
	// existing authenticator entries keep the old label, since the issuer is
	// baked into the enrollment URI and cannot be updated remotely.
	AppName string
	// AppVersion is the build identifier reported by the health endpoint and the
	// startup banner.
	AppVersion string

	// AppBaseURL is the engine's own public URL, used to build links in emails,
	// OAuth callbacks and SAML metadata. It must be the address a browser
	// reaches, which behind a TLS-terminating proxy is the https:// one.
	AppBaseURL string
	// Issuer is the OpenID Connect issuer identifier placed in the `iss` claim
	// of every token and published at the discovery endpoint. Changing it
	// invalidates tokens that relying parties have already accepted.
	Issuer string

	// ---------------------------------------------------------------------
	// Cross-origin requests (CORS)
	// ---------------------------------------------------------------------

	// CORSAllowedOrigins lists the browser origins permitted to call this API.
	//
	// With CORSAllowCredentials enabled, a wildcard is refused by Validate: a
	// server that reflects any origin and allows credentials lets any website a
	// signed-in user visits make authenticated calls with their cookies and read
	// the replies.
	CORSAllowedOrigins []string
	// CORSAllowedMethods lists permitted HTTP methods for cross-origin requests.
	CORSAllowedMethods []string
	// CORSAllowedHeaders lists request headers a browser may send cross-origin.
	CORSAllowedHeaders []string
	// CORSAllowCredentials permits cookies and Authorization headers on
	// cross-origin requests. Required for cookie-based sessions in a browser.
	CORSAllowCredentials bool
	// CORSMaxAge is how long a browser may cache the preflight result.
	CORSMaxAge time.Duration

	// ---------------------------------------------------------------------
	// Database
	// ---------------------------------------------------------------------

	// DatabaseURL is the connection string. Its scheme selects the driver, so
	// no separate "database type" setting exists to fall out of sync:
	//
	//   postgres://user:pass@host:5432/authn?sslmode=require
	//   mysql://user:pass@host:3306/authn
	//   sqlite://file:authn.db?_fk=1
	DatabaseURL string
	// DatabaseMaxOpenConns caps total open connections. Set it below the
	// server's own connection limit divided by the number of instances.
	DatabaseMaxOpenConns int
	// DatabaseMaxIdleConns caps connections kept ready for reuse.
	DatabaseMaxIdleConns int
	// DatabaseConnMaxLifetime retires connections after this age, so instances
	// pick up failovers and DNS changes instead of holding a dead socket.
	DatabaseConnMaxLifetime time.Duration
	// DatabaseAutoMigrate runs schema migration at startup. Convenient in
	// development; in production prefer a reviewed migration step so schema
	// changes are not applied by whichever instance boots first.
	DatabaseAutoMigrate bool

	// ---------------------------------------------------------------------
	// Redis
	// ---------------------------------------------------------------------

	// RedisURL is the cache and rate-limit store connection string.
	RedisURL string
	// RedisRequired makes an unreachable Redis a startup failure rather than a
	// degraded start. Rate limiting depends on Redis for shared state, so
	// running without it across several instances weakens brute-force defence.
	RedisRequired bool

	// ---------------------------------------------------------------------
	// Cryptographic secrets
	// ---------------------------------------------------------------------

	// EncryptionKey is the AES-256-GCM key protecting secrets at rest, such as
	// stored TOTP seeds and provider credentials. Rotating it makes existing
	// ciphertext unreadable.
	EncryptionKey string
	// APIKeyPepper is mixed into API key hashes. It is not stored alongside the
	// hashes, so a database-only leak still cannot be brute-forced offline.
	APIKeyPepper string
	// JWTKeyID identifies the active signing key in the published JWKS.
	JWTKeyID string
	// JWTSigningKeyPath is the RSA private key used to sign OIDC ID tokens.
	JWTSigningKeyPath string

	// ---------------------------------------------------------------------
	// Token and session lifetimes
	// ---------------------------------------------------------------------

	// AccessTokenTTL is how long an access token stays valid. Short lifetimes
	// limit the damage of a leaked token, at the cost of more refreshes.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a session can be refreshed before the user
	// must sign in again.
	RefreshTokenTTL time.Duration
	// SessionGracePeriod lets a just-rotated refresh token work briefly, so
	// concurrent in-flight requests during rotation are not all logged out.
	SessionGracePeriod time.Duration
	// EmailVerificationTTL is the lifetime of an email verification link.
	EmailVerificationTTL time.Duration
	// MagicLinkTTL is the lifetime of a passwordless sign-in link. Kept short
	// because the link alone grants a session.
	MagicLinkTTL time.Duration
	// MFAChallengeTTL is how long the token issued between password success and
	// second-factor entry remains valid.
	MFAChallengeTTL time.Duration
	// SocialAuthStateTTL is the lifetime of the CSRF state for a social login
	// round trip.
	SocialAuthStateTTL time.Duration
	// OAuthCodeTTL is the lifetime of an OAuth authorization code. The spec
	// recommends a maximum of ten minutes as codes are single-use.
	OAuthCodeTTL time.Duration
	// IDTokenTTL is the lifetime of an OIDC ID token.
	IDTokenTTL time.Duration
	// RecoveryTokenTTL is the lifetime of an account-recovery token.
	RecoveryTokenTTL time.Duration
	// InvitationTTL is the default lifetime of an organization invitation when
	// the caller does not specify one.
	InvitationTTL time.Duration

	// ---------------------------------------------------------------------
	// Rate limiting
	// ---------------------------------------------------------------------

	// RateLimitEnabled turns request throttling on. Disable only in tests.
	RateLimitEnabled bool
	// RateLimitMaxAttempts is the number of attempts allowed per window for a
	// single account.
	RateLimitMaxAttempts int
	// RateLimitWindow is the period over which attempts are counted.
	RateLimitWindow time.Duration
	// RateLimitIPBudgetMultiplier widens the per-IP allowance relative to the
	// per-account one, so a shared office or mobile-carrier address is not
	// locked out by one user's typos.
	RateLimitIPBudgetMultiplier int
	// RateLimitBackoffSchedule is the escalating lockout applied to repeat
	// offenders, longest last.
	RateLimitBackoffSchedule []time.Duration
	// RateLimitViolationResetDays is how long a clean record must last before
	// an offender's escalation level returns to zero.
	RateLimitViolationResetDays int
	// RateLimitFailClosed rejects requests when the limiter's backing store is
	// unavailable, rather than allowing them through unchecked.
	RateLimitFailClosed bool

	// ResendRateLimitEnabled throttles verification-email resends per address.
	ResendRateLimitEnabled bool
	// ResendRateLimitMaxAttempts is the resend allowance per window.
	ResendRateLimitMaxAttempts int
	// ResendRateLimitWindow is the resend counting period.
	ResendRateLimitWindow time.Duration

	// ---------------------------------------------------------------------
	// Email delivery
	// ---------------------------------------------------------------------

	// EmailDriver selects the delivery backend. "noop" logs instead of sending,
	// which is the safe default for local development.
	EmailDriver string
	// EmailFromAddress is the sender address on outbound mail.
	EmailFromAddress string
	// EmailFromName is the display name shown beside the sender address.
	EmailFromName string

	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string

	ResendAPIKey        string
	SendGridAPIKey      string
	PostmarkServerToken string

	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string

	// ---------------------------------------------------------------------
	// SMS delivery
	// ---------------------------------------------------------------------

	// SMSDriver selects the SMS backend, or "noop" to log instead of send.
	SMSDriver string

	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFromNumber string

	MessageBirdAccessKey  string
	MessageBirdOriginator string

	// ---------------------------------------------------------------------
	// WebAuthn / passkeys
	// ---------------------------------------------------------------------

	// WebAuthnRPID is the domain passkeys are bound to, without scheme or port.
	//
	// Changing it invalidates every enrolled passkey, because the browser
	// refuses to release a credential registered under a different domain.
	WebAuthnRPID string
	// WebAuthnRPOrigins lists the full origins allowed to start a passkey
	// ceremony. Each must be a scheme://host[:port] resolving to WebAuthnRPID.
	WebAuthnRPOrigins []string
	// WebAuthnRPDisplayName is the application name the browser shows during
	// enrolment.
	WebAuthnRPDisplayName string

	// ---------------------------------------------------------------------
	// SAML
	// ---------------------------------------------------------------------

	// SAMLAssertionConsumerPath is the path where identity providers post SAML
	// assertions. Combined with AppBaseURL it forms the absolute URL published
	// in service-provider metadata.
	SAMLAssertionConsumerPath string

	// ---------------------------------------------------------------------
	// Background workers
	// ---------------------------------------------------------------------

	// WebhookWorkerCount is how many goroutines deliver webhooks concurrently.
	//
	// It bounds how much outbound traffic one instance aims at a subscriber, so a
	// slow endpoint cannot consume the whole process. Raising it increases
	// throughput and the load a subscriber sees at once.
	WebhookWorkerCount int
	// DegradedModeCheckInterval is how often the engine probes Redis to decide
	// whether it is running in degraded mode.
	//
	// Shorter notices an outage sooner at the cost of more probes; longer leaves
	// the engine reporting healthy after Redis has gone.
	DegradedModeCheckInterval time.Duration

	// ---------------------------------------------------------------------
	// Organizations
	// ---------------------------------------------------------------------

	// OrgMetadataMaxBytes caps the JSON metadata blob stored on an organization,
	// bounding how much caller-controlled data a single row can hold.
	OrgMetadataMaxBytes int

	// ---------------------------------------------------------------------
	// Feature flags
	// ---------------------------------------------------------------------

	FeaturePush2FAEnabled       bool
	FeatureMagicLinkEnabled     bool
	FeatureWebhooksEnabled      bool
	FeatureRBACEnabled          bool
	FeatureImpersonationEnabled bool
}

// IsProduction reports whether the engine is running in the production tier.
func (c *Config) IsProduction() bool { return c.Env == EnvProduction }

// Address returns the "host:port" string to bind the HTTP listener to.
func (c *Config) Address() string {
	return c.Host + ":" + itoa(c.Port)
}

// CookieSecure reports whether session cookies must carry the Secure attribute,
// which tells the browser to send them over HTTPS only.
//
// It is derived from AppBaseURL's scheme rather than being a separate setting,
// so the two cannot disagree. Hardcoding false would ship long-lived refresh
// tokens over cleartext HTTP where any network observer could replay them;
// hardcoding true would break plaintext local development, because a Secure
// cookie is never sent over HTTP to a non-localhost origin.
func (c *Config) CookieSecure() bool {
	return strings.HasPrefix(strings.ToLower(c.AppBaseURL), "https://")
}

// SocialCallbackURL returns the absolute redirect URI to register in a social
// provider's console for the given provider ("google", "github", ...).
//
// Deriving it from AppBaseURL means a deployment that moves domains updates one
// variable rather than one entry per provider.
func (c *Config) SocialCallbackURL(provider string) string {
	return c.AppBaseURL + "/v1/client/auth/social/" + provider + "/callback"
}

// SAMLAssertionConsumerURL returns the absolute ACS endpoint published in
// service-provider metadata and registered with each identity provider.
func (c *Config) SAMLAssertionConsumerURL() string {
	return c.AppBaseURL + c.SAMLAssertionConsumerPath
}

// itoa converts a non-negative int to a string without pulling in strconv at
// every call site. Port values are already range-checked by the loader.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [6]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
