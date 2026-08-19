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
	// Tenant provisioning and the hosted control plane
	// ---------------------------------------------------------------------

	// PlatformTenantID is the tenant whose end users are the operators of a
	// hosted deployment — the control plane, running as a tenant of itself.
	//
	// Empty disables the hosted front door entirely, which is the self-hosted
	// default: the platform routes answer 404 rather than 403, so a deployment
	// that has no control plane does not advertise one.
	PlatformTenantID string
	// PlatformTenantSlug is that tenant's slug, reserved so no customer can
	// provision over the control plane. Idempotency-by-slug makes this matter:
	// without the reservation, a caller naming it would be handed the existing
	// control-plane tenant rather than a new one.
	PlatformTenantSlug string

	// CookieDomain scopes session cookies to a parent domain, so sibling apps on
	// subdomains share one login — "auth.acme.com" issuing a cookie for
	// ".acme.com" is sent by the browser to "app.acme.com" and
	// "admin.acme.com" alike.
	//
	// This is the one session setting that stays in the environment rather than
	// moving to the tenant row, and not for convenience: a browser only accepts a
	// cookie for a domain the responding server is itself within. An engine
	// served from api.authn.com physically cannot set a cookie for .acme.com, no
	// matter what a customer configures. The value is bound to the deployment's
	// DNS, so it belongs beside the deployment's other DNS-bound settings.
	//
	// Empty — the default — produces a host-only cookie, which is correct for a
	// single-domain deployment and for local development. Customers whose apps
	// live on genuinely unrelated domains are served by the OAuth redirect flow
	// instead, which needs no shared cookie at all.
	CookieDomain string

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
	// RetentionSweepInterval is how often the background sweep deletes records
	// whose retention window has elapsed. Zero or negative falls back to the
	// sweeper's own default rather than disabling the sweep, because a deployment
	// that never sweeps grows without bound.
	RetentionSweepInterval time.Duration
	// SupersededSessionRetention is how long a session row that a refresh replaced
	// is kept after its grace window closes. The row's only remaining purpose is
	// to let a replay of its refresh token be recognised as token reuse rather
	// than as an unknown credential, so this is the width of that detection
	// window. It is also the highest-volume class of row in the schema — one per
	// refresh — which is why it is kept far more briefly than the rest.
	SupersededSessionRetention time.Duration
	// TerminalSessionRetention is how long an expired or revoked session row is
	// kept past its expiry. These rows carry the device, address and location
	// history a user reads back from the session list, so the window is normally
	// at least RefreshTokenTTL to keep that history complete.
	TerminalSessionRetention time.Duration
	// RetentionBatchSize bounds how many rows one delete statement removes. Small
	// batches keep each statement short, so a sweep of a long-neglected table does
	// not hold locks or extend the write-ahead log for minutes at a time.
	RetentionBatchSize int
	// SandboxMessageRetention is how long a captured test-environment message is
	// kept before the sweep removes it. Captures hold verification links and
	// one-time codes in plain text so a harness can read them, which makes a long
	// window an accumulating archive of usable credentials rather than a
	// convenience — a test reads its message within seconds of triggering it.
	SandboxMessageRetention time.Duration
	// TestUserRetention is how long a test-environment account is kept past its last
	// sign-in before the sweep deletes it along with everything hanging off it.
	// Suites create accounts by the thousand and abandon them, so without a window
	// they accumulate until they reach TestMaxUsers and start failing runs that have
	// nothing wrong with them. Live accounts are never swept: an idle customer is
	// still a customer.
	TestUserRetention time.Duration
	// TestAccessTokenTTL is the ceiling on a test-environment access token's
	// lifetime. A harness needing one for longer than a few minutes is running
	// something other than a test, and until it expires the token is a bearer
	// credential for whoever has read it out of a log.
	TestAccessTokenTTL time.Duration
	// TestSessionTTL is the ceiling on a test-environment session's lifetime, and so
	// on how long its refresh token keeps minting access tokens. A test signs in when
	// it runs, so nothing there needs a session that survives to the next run, and a
	// month-long one is a live credential idling in a sandbox nobody watches.
	TestSessionTTL time.Duration
	// TestMaxUsers is the ceiling on how many users one tenant may hold in the test
	// environment. A test environment is free and unmetered, so the ceiling is what
	// keeps it a development surface rather than the cheapest place to run a
	// product: it sits far above what any suite needs and far below a user base.
	TestMaxUsers int
	// TestMaxOrganizations is the ceiling on a tenant's test-environment
	// organizations. An organization carries an environment of its own, so a tenant's
	// live workspaces neither count against this nor are refused by it.
	TestMaxOrganizations int
	// TestMaxAPIKeys is the ceiling on test API keys for one tenant, counting the
	// pair provisioning installs alongside a new application.
	TestMaxAPIKeys int
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

	// SAMLSPEntityIDPrefix is the namespace the service-provider entity ID is
	// built from: the organization ID is appended to it.
	//
	// The entity ID is an opaque identifier an identity provider records for this
	// service provider — it does not have to resolve. It is published in SP
	// metadata AND checked against an assertion's AudienceRestriction, so both
	// uses must derive from this one setting or every audience-restricted
	// assertion is rejected. Changing it after a provider has been configured
	// requires re-registering there.
	SAMLSPEntityIDPrefix string

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

// dataEnvironmentTest names the test data environment — the one a tenant's test
// keys address, holding its own users, applications and settings.
//
// It is deliberately not EnvTest above. That constant names a deployment tier,
// and the two are independent: a production deployment serves both data
// environments, and a development one serves live data to whoever configured it.
const dataEnvironmentTest = "test"

// AccessTokenTTLFor returns the access token lifetime to sign for environment.
func (c *Config) AccessTokenTTLFor(environment string) time.Duration {
	return c.ClampAccessTokenTTL(environment, c.AccessTokenTTL)
}

// RefreshTokenTTLFor returns the session lifetime to record for environment.
func (c *Config) RefreshTokenTTLFor(environment string) time.Duration {
	return c.ClampSessionTTL(environment, c.RefreshTokenTTL)
}

// ClampAccessTokenTTL bounds ttl by the test-environment access token ceiling.
//
// It takes a lifetime rather than reading one, so a value resolved elsewhere — a
// tenant's own session policy, which may ask for a day — passes through the same
// ceiling as the deployment default.
func (c *Config) ClampAccessTokenTTL(environment string, ttl time.Duration) time.Duration {
	return clampTestTTL(environment, ttl, c.TestAccessTokenTTL)
}

// ClampSessionTTL bounds ttl by the test-environment session ceiling.
//
// It governs the session row and the refresh cookie alike, so the credential and
// the record it refreshes against expire together rather than leaving a browser
// holding a cookie for a session the database dropped weeks earlier.
func (c *Config) ClampSessionTTL(environment string, ttl time.Duration) time.Duration {
	return clampTestTTL(environment, ttl, c.TestSessionTTL)
}

// clampTestTTL returns ttl, or ceiling when environment is the test one and ttl
// runs past it. It lowers and never raises, so a deployment or tenant that asked
// for something shorter keeps it, and live is returned untouched.
//
// A non-positive ceiling leaves the lifetime alone. That is the safe reading of an
// unset field: a zero-valued Config — one nobody loaded — bounds nothing, where a
// zero read as "expire immediately" would take out every test sign-in. The loader
// refuses a non-positive duration, so a configured deployment is always bounded.
func clampTestTTL(environment string, ttl, ceiling time.Duration) time.Duration {
	if environment != dataEnvironmentTest || ceiling <= 0 || ttl <= ceiling {
		return ttl
	}
	return ceiling
}

// SocialCallbackURL returns the absolute redirect URI to register in a social
// provider's console for the given provider ("google", "github", ...).
//
// Deriving it from AppBaseURL means a deployment that moves domains updates one
// variable rather than one entry per provider.
func (c *Config) SocialCallbackURL(provider string) string {
	return c.AppBaseURL + "/v1/client/auth/social/" + provider + "/callback"
}

// SAMLSPEntityID returns the service-provider entity ID for an organization.
//
// Metadata publishing and audience validation both call this, so the value an
// identity provider is told and the value an assertion is checked against can
// never disagree.
func (c *Config) SAMLSPEntityID(organizationID string) string {
	return c.SAMLSPEntityIDPrefix + organizationID
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
