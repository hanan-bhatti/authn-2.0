//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/harness_test.go
 * Tier: Integration Test Harness
 *
 * Shared setup for the integration tests in this package. Each test boots the
 * real authentication and OAuth handlers against a private in-memory SQLite
 * database and drives them through Fiber's in-process test transport, so no
 * test needs a listening port, a fixed port number or a sleep to wait for a
 * server to come up.
 *
 * Outbound email is captured rather than delivered. The engine puts the
 * verification and magic-link tokens in the message body, so capturing the
 * message is what lets these tests complete a real token round trip without an
 * SMTP catcher running alongside them.
 *
 * Capture goes through the engine's own sandbox rather than around it, because
 * these tests run in the test environment and that is what the test environment
 * does. A harness that intercepted mail ahead of the sandbox would be testing an
 * arrangement no deployment runs, and would report a broken sandbox as a passing
 * suite.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/appconfig"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/audit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/org"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/platform"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/provisioning"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/quota"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sandbox"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/settings"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/useradmin"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// publishableKey is the API key the seeded test application accepts. It matches
// the demo key the seeder installs, so a request captured from local
// development can be replayed against this harness unchanged.
const publishableKey = "pk_test_demo12345678901234567890123456789012"

// secretKey is the backend credential the admin surface accepts, belonging to the
// same seeded application. The admin guard takes either this or a console JWT,
// and the secret-key path is the one a test can present without first standing up
// an administrator account and a second-factor enrolment.
const secretKey = "sk_test_demo12345678901234567890123456789012"

// liveSecretKey is a secret key addressing the live environment of the same
// application.
//
// It exists so a test can present a credential that is valid and admits nothing:
// the environment a request acts in follows its key, so this is how the
// test-environment-only surfaces are asked to refuse.
const liveSecretKey = "sk_live_demo12345678901234567890123456789012"

// testTenant and testEnvironment are the tenant and environment every request
// in this package is scoped to. testApplication is the application the
// publishable key above belongs to.
const (
	testTenant      = "tnt_00000000000000000000000000000001"
	testEnvironment = "test"
	testApplication = "app_00000000000000000000000000000001"
)

// platformTenantSlug is the slug the harness reserves for the control plane.
//
// The seeded tenant doubles as the platform tenant, which is what the real hosted
// deployment looks like: the control plane is one tenant among the rest, and its
// end users are the customers who provision tenants of their own.
//
// The value is deliberately absent from the provisioning package's own built-in
// reservations. A slug that appeared on both lists would be refused either way, so
// a test could not tell whether the deployment's configured slug was reaching the
// provisioner at all.
const platformTenantSlug = "authn-console"

// requestTimeoutMillis bounds a single in-process request. It is far above any
// healthy response time because Argon2id password hashing deliberately costs
// hundreds of milliseconds, and signup performs one on the request path.
const requestTimeoutMillis = 30_000

// testFrontendBaseURL is the deployment-wide origin the booted engine prefixes to
// emailed links, standing in for WEB_ACCOUNT_URL.
//
// A host the engine does not itself serve, so a link that still pointed at the API
// would be visible rather than indistinguishable from a correct one.
const testFrontendBaseURL = "http://account.test"

// testApplicationFrontendBaseURL is the per-application override a suite writes to
// the application row to check that it wins over testFrontendBaseURL.
const testApplicationFrontendBaseURL = "https://app.example.test/ui"

// sessionGracePeriod is how long a just-rotated refresh token keeps working.
// It is short so the grace-window tests spend a beat waiting rather than the
// ten-plus seconds a production-shaped value would demand.
const sessionGracePeriod = 1500 * time.Millisecond

// databaseSeq numbers the in-memory databases so each testEnv gets its own.
//
// SQLite keys a shared-cache in-memory database by name, so reusing one name
// would let users seeded by one test satisfy or collide with another's
// assertions depending on run order.
var databaseSeq atomic.Uint64

// memoryDSN returns a connection string for a fresh in-memory SQLite database.
func memoryDSN() string {
	return fmt.Sprintf("file:authn_integration_%d?mode=memory&cache=shared&_fk=1", databaseSeq.Add(1))
}

// captureEmailProvider implements email.EmailProvider by recording messages
// instead of sending them.
//
// It sits behind the sandbox as the provider a message reaches when it is not
// captured, which is where a send made off the request path — on a context
// carrying no environment — arrives.
type captureEmailProvider struct {
	mu   sync.Mutex
	sent []emailMessage
}

// emailMessage is one captured outbound email.
type emailMessage struct {
	to      string
	subject string
	html    string
	text    string
}

// Send records the message and always succeeds, so a test never fails on
// delivery problems it is not trying to exercise.
func (p *captureEmailProvider) Send(_ context.Context, to, subject, htmlBody, textBody string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, emailMessage{to: to, subject: subject, html: htmlBody, text: textBody})
	return nil
}

// messagesTo returns every captured message addressed to the given recipient,
// oldest first.
func (p *captureEmailProvider) messagesTo(recipient string) []emailMessage {
	p.mu.Lock()
	defer p.mu.Unlock()

	var out []emailMessage
	for _, m := range p.sent {
		if strings.EqualFold(m.to, recipient) {
			out = append(out, m)
		}
	}
	return out
}

// tokenFor extracts the value of the "token" query parameter from the most
// recent message sent to recipient.
//
// Returns the raw token and true on success. Returns false when no message
// reached that recipient or the newest one carries no token, which lets a
// caller report the specific failure rather than asserting on an empty string.
func (p *captureEmailProvider) tokenFor(recipient string) (string, bool) {
	messages := p.messagesTo(recipient)
	if len(messages) == 0 {
		return "", false
	}

	newest := messages[len(messages)-1]
	body := newest.html
	if body == "" {
		body = newest.text
	}

	return tokenFromBody(body)
}

// tokenFromBody pulls the "token" query parameter out of a rendered message.
//
// Returns false when the body carries no token, so a caller can report that
// rather than asserting against an empty string.
func tokenFromBody(body string) (string, bool) {
	idx := strings.Index(body, "token=")
	if idx == -1 {
		return "", false
	}

	token := body[idx+len("token="):]
	// The token sits inside an href or a bare URL, so it ends at the first
	// character that cannot appear in a query value.
	if end := strings.IndexAny(token, "\"'<> \t\r\n&"); end != -1 {
		token = token[:end]
	}
	if token == "" {
		return "", false
	}
	return token, true
}

// linkFromBody returns the whole URL carrying the "token" query parameter,
// including its scheme and host.
//
// The boundaries are found by walking outward from the parameter rather than by
// looking for "http", so a link rendered with no scheme at all comes back as it
// stands. That is the failure worth catching here — an origin-less link is not
// openable from a mail client — and an assertion naming what it received says more
// than one reporting no link was found.
func linkFromBody(body string) (string, bool) {
	idx := strings.Index(body, "token=")
	if idx == -1 {
		return "", false
	}

	start := strings.LastIndexAny(body[:idx], "\"'<>( \t\r\n")
	link := body[start+1:]
	if end := strings.IndexAny(link, "\"'<>) \t\r\n"); end != -1 {
		link = link[:end]
	}
	if link == "" {
		return "", false
	}
	return link, true
}

// captureSMSProvider implements sms.SMSProvider by recording messages instead of
// sending them.
//
// Like the email recorder it sits behind the sandbox, so it holds only the text
// messages that were meant to reach a carrier rather than the sandbox inbox.
type captureSMSProvider struct {
	mu   sync.Mutex
	sent []smsMessage
}

// smsMessage is one captured outbound text message.
type smsMessage struct {
	to   string
	body string
}

// SendSMS records the message and always succeeds.
func (p *captureSMSProvider) SendSMS(_ context.Context, toPhoneNumber, message string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, smsMessage{to: toPhoneNumber, body: message})
	return nil
}

// messagesTo returns every captured text message addressed to the given number,
// oldest first.
func (p *captureSMSProvider) messagesTo(number string) []smsMessage {
	p.mu.Lock()
	defer p.mu.Unlock()

	var out []smsMessage
	for _, m := range p.sent {
		if m.to == number {
			out = append(out, m)
		}
	}
	return out
}

// testEnv is one in-process engine instance under test.
type testEnv struct {
	factory *clientfactory.ClientFactory
	cfg     *config.Config
	// emails is the provider behind the sandbox, holding only the messages that
	// were delivered rather than captured.
	emails *captureEmailProvider
	// texts is the SMS provider behind the sandbox, on the same terms as emails.
	texts *captureSMSProvider
	// sandboxStore is the store the test environment's messages are captured into,
	// and what tokenFor reads.
	sandboxStore *sandbox.Store
	policyRepo   *policy.Repository
	authRepo     *auth.Repository
	app          *fiber.App
}

// envSettings collects the deviations from the default harness a suite asks for.
//
// The zero value is what every test got before there was anything to vary, so a
// suite that supplies no option boots the same engine it always did.
type envSettings struct {
	// testLimits bounds how much the booted engine lets a tenant hold in the test
	// environment. Empty leaves the engine unbounded.
	testLimits quota.Limits
	// testAccessTokenTTL and testSessionTTL are the test-environment lifetime
	// ceilings. Zero leaves the engine unbounded, which is what every suite but the
	// one asserting on them wants: the harness signs in against a test key, so a
	// ceiling applied everywhere would silently shorten every credential the other
	// suites reason about.
	testAccessTokenTTL time.Duration
	testSessionTTL     time.Duration
}

// envOption adjusts the engine a test boots.
type envOption func(*envSettings)

// withTestLimits boots the engine with test-environment ceilings in force.
//
// Only the suite that asserts on a ceiling asks for one. Applying ceilings
// everywhere would put every other suite one fixture away from a refusal that has
// nothing to do with what it is testing.
func withTestLimits(limits quota.Limits) envOption {
	return func(s *envSettings) { s.testLimits = limits }
}

// withTTLCeilings boots the engine with test-environment lifetime ceilings.
//
// Both must be shorter than the deployment defaults below for a clamp to be
// observable at all: a ceiling equal to the default cannot be told from no ceiling.
func withTTLCeilings(accessTokenTTL, sessionTTL time.Duration) envOption {
	return func(s *envSettings) {
		s.testAccessTokenTTL = accessTokenTTL
		s.testSessionTTL = sessionTTL
	}
}

// newTestEnv builds a wired engine: a private in-memory schema, a seeded
// tenant, application and publishable key, the capturing email provider, and
// the authentication and OAuth handlers mounted on a Fiber app.
//
// rateLimiter and resendLimiter may be nil, which leaves the matching routes
// unthrottled exactly as the real server does when rate limiting is off.
//
// The database is closed automatically when the test finishes.
func newTestEnv(t *testing.T, rateLimiter, resendLimiter *ratelimit.Limiter, opts ...envOption) *testEnv {
	t.Helper()

	var chosen envSettings
	for _, opt := range opts {
		opt(&chosen)
	}

	dsn := memoryDSN()
	factory, err := clientfactory.NewClientFactory("sqlite3", dsn)
	if err != nil {
		t.Fatalf("opening in-memory database: %v", err)
	}
	t.Cleanup(func() {
		if err := factory.Close(); err != nil {
			t.Errorf("closing database: %v", err)
		}
	})

	// Applied here rather than at the call site so the ceilings sit behind the
	// privacy interceptors the factory has just installed, which is the order the
	// server builds its client in and the order that makes a count per tenant.
	factory.ApplyTestLimits(chosen.testLimits)

	cfg := &config.Config{
		Env:           config.EnvTest,
		DatabaseURL:   dsn,
		EncryptionKey: "super_secret_32_byte_kms_encryption_key_authn_2026!",
		APIKeyPepper:  "super_secret_32_byte_api_key_pepper_authn_2026!",
		// The loader defaults this and refuses anything that is not an absolute
		// http(s) URL, so a deployment always has one. Leaving it empty here would
		// render links with no scheme or host — a shape no deployment emits, which
		// anything reading a link out of a message would then be tested against.
		AppBaseURL: "http://localhost:8080",
		// Deliberately a different origin from AppBaseURL, so an assertion that a
		// link opens the frontend cannot pass against the engine's own host.
		FrontendBaseURL:    testFrontendBaseURL,
		JWTSigningKeyPath:  "./keys/rsa_private.pem",
		EmailDriver:        "noop",
		RateLimitEnabled:   rateLimiter != nil,
		SessionGracePeriod: sessionGracePeriod,
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    720 * time.Hour,
		TestAccessTokenTTL: chosen.testAccessTokenTTL,
		TestSessionTTL:     chosen.testSessionTTL,
		// The seeded tenant is also the control plane, so the platform routes mount
		// and a user who signs up through the ordinary client routes is a platform
		// member — the same arrangement the hosted deployment runs.
		PlatformTenantID:   testTenant,
		PlatformTenantSlug: platformTenantSlug,
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeyService := apikey.NewService(apiKeyRepo, cfg.APIKeyPepper)
	pkMiddleware := middleware.RequirePublishableKey(apiKeyService)

	policyRepo := policy.NewRepository(factory)
	emails := &captureEmailProvider{}
	texts := &captureSMSProvider{}

	// The provider is wrapped exactly as the server wraps it, so a send made while
	// acting in the test environment is captured by the engine rather than by the
	// harness. Sends on a bypassing context still reach the recorder behind it.
	sandboxStore := sandbox.NewStore(factory)
	var emailProvider email.EmailProvider = sandbox.WrapEmail(emails, sandboxStore)

	authRepo := auth.NewRepository(factory)
	authService := auth.NewService(authRepo, cfg, emailProvider)

	// The resolver is attached with a nil cache, so every read goes to the
	// database. That matches the server's degraded path and keeps a test from
	// asserting against a value another test left in a shared cache.
	settingsResolver := settings.NewResolver(factory, policyRepo, nil, 0)

	// Emailed links consult the calling application's own origin before the
	// deployment default, exactly as the server wires them. Without this the suite
	// would only ever exercise the default, and a per-application override could
	// break without a test noticing.
	authService = authService.WithFrontendURLResolver(settingsResolver)

	authHandler := auth.NewHandler(authService, policyRepo, rateLimiter, resendLimiter).
		WithSessionPolicyResolver(settingsResolver)

	oauthRepo := oauth.NewRepository()
	oauthService := oauth.NewService(oauthRepo, authRepo, authService, cfg)
	oauthHandler := oauth.NewHandler(oauthService)

	// The session handler owns sign-out and the client session routes, and it
	// gets the same resolver the server gives it so its cookie writes are driven
	// by stored tenant policy rather than the deployment default.
	sessionRepo := session.NewRepository(factory)
	sessionService := session.NewService(sessionRepo, cfg)
	sessionHandler := session.NewHandler(sessionService).
		WithSessionPolicyResolver(settingsResolver)

	authHandler.RegisterRoutes(app, pkMiddleware)
	oauthHandler.RegisterRoutes(app, pkMiddleware)
	// The admin slot is nil: no test drives the admin session routes, and passing
	// the publishable-key middleware there would mount routes that act on an
	// arbitrary user ID behind a credential that establishes no identity.
	sessionHandler.RegisterRoutes(app, pkMiddleware, nil)

	// The administrative user directory. The guard is the real one, since what the
	// tests assert about these routes — that they reach only the caller's tenant,
	// and that a restriction placed through them is refused by the auth paths —
	// is a property of the guard and the handler acting together.
	//
	// No second-factor validator is supplied. It constrains console operators only,
	// and these tests authenticate with a secret key, which names a key rather than
	// a person and has no factor to enrol.
	adminMiddleware := middleware.RequireAdminAuth(apiKeyService, cfg.EncryptionKey, nil)
	useradmin.NewHandler(
		useradmin.NewService(useradmin.NewRepository(factory), sessionRepo, nil, cfg),
	).RegisterRoutes(app, adminMiddleware)

	// The audit trail, behind the same guard. It is mounted with the real one
	// because the entries name who signed in and from where, so who may read them
	// is as much a part of the route as what it returns.
	audit.NewHandler(factory).RegisterRoutes(app, adminMiddleware)

	// Key issuance, behind the same guard. The route is here so a ceiling can be
	// driven against a tenant that is not starting from zero: provisioning has
	// already installed the keys below, and a ceiling that ignored them would be
	// counting something other than what the tenant holds.
	apikey.NewHandler(apiKeyService).RegisterRoutes(app, adminMiddleware)

	// The sandbox inbox and delivery verification, behind the same guard the server
	// puts them behind. The providers handed to the handler are the ones behind the
	// sandbox, matching the server: verification exists to reach a provider, so it
	// must not be routed back into the capture it is trying to bypass.
	//
	// The resend limiter is the one the server gives it, so the route is bounded
	// here whenever a test supplies a limiter and unbounded when it does not.
	sandbox.NewHandler(sandboxStore, factory, cfg, emails, texts).
		WithLimiter(resendLimiter).
		RegisterRoutes(app, adminMiddleware)

	// The bootstrap document a sign-in page fetches before it renders, mounted with
	// both of its guards. The pairing is the point: the document is public, and the
	// branding that shapes it is not, so the two credentials have to be tested
	// against the same handler rather than against a stand-in for either one.
	appconfig.NewHandler(
		appconfig.NewService(appconfig.NewRepository(factory), policyRepo, settingsResolver, cfg),
	).RegisterRoutes(app, pkMiddleware, adminMiddleware)

	// Webhook management, behind the same admin guard the server uses. Which
	// credential may change the endpoint list is a property of the routes rather
	// than of the service, so it is only reachable through the mounted handler.
	//
	// The dispatcher is constructed but never started: no test here asserts on a
	// delivered event, and an unstarted dispatcher queues into its buffer rather
	// than spawning workers the harness would then have to shut down.
	webhookRepo := webhook.NewRepository(factory)
	webhook.NewHandler(
		webhook.NewService(webhookRepo,
			webhook.NewDispatcher(webhookRepo, cfg.EncryptionKey, cfg.WebhookWorkerCount), cfg),
	).RegisterRoutes(app, adminMiddleware)

	// SAML, on both tiers, mounted before the organization families below for the
	// same reason they are mounted last: the client tier attaches a session
	// requirement to the whole /v1/client prefix, and Fiber applies prefix
	// middleware to whatever is registered after it.
	//
	// The dispatcher is nil, matching the organization block: nothing here asserts
	// on a delivered event.
	saml.NewHandler(saml.NewService(factory, nil, sessionRepo, cfg)).
		RegisterRoutes(app, pkMiddleware, adminMiddleware)

	// Organizations, on both tiers, because the tiers differ in who the actor is
	// rather than in what they reach. A client-tier caller needs an end-user session
	// on top of the publishable key, since the service resolves membership from it;
	// the tenant tier presents an administrative credential and acts across every
	// organization in the tenant.
	//
	// Mounted after every other /v1/client family, as the server mounts it. The
	// client tier attaches its session requirement to the whole /v1/client prefix,
	// and Fiber applies prefix middleware to the routes registered after it, so
	// moving this block earlier would put a bearer token in front of the public
	// bootstrap document.
	//
	// The dispatcher is nil, which the service reads as "webhooks are off"; nothing
	// here asserts on a delivered event.
	org.NewHandler(org.NewService(factory, nil, cfg)).RegisterRoutes(app,
		middleware.RequireClientAuth(cfg.EncryptionKey, nil), pkMiddleware, adminMiddleware)

	// The control plane gets the real guard rather than a stand-in, because the
	// properties worth testing here — that provisioning attributes ownership to the
	// signed-in caller and that an unverified address cannot reach it — are
	// properties of the guard and the handler acting together.
	//
	// The blocklist is nil, which IsBlocked handles as "nothing is revoked"; token
	// revocation is covered by the middleware's own unit tests.
	platformHandler := platform.NewHandler(
		provisioning.NewService(factory, apiKeyService),
		platform.NewRepository(factory),
		rateLimiter,
		cfg.PlatformTenantSlug,
	)
	platformHandler.RegisterRoutes(app,
		middleware.RequirePlatformAuth(cfg.EncryptionKey, cfg.PlatformTenantID, nil, authRepo))

	ctx := privacy.NewBypassContext(context.Background())
	if err := authRepo.EnsureTenantExists(ctx, testTenant); err != nil {
		t.Fatalf("seeding tenant: %v", err)
	}
	if err := authRepo.EnsureDefaultApplicationExists(ctx, testApplication, testTenant, []string{"http://localhost:3000/callback"}); err != nil {
		t.Fatalf("seeding application: %v", err)
	}
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_00000000000000000000000000000001", testApplication, publishableKey, cfg.APIKeyPepper); err != nil {
		t.Fatalf("seeding API key: %v", err)
	}
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_00000000000000000000000000000002", testApplication, secretKey, cfg.APIKeyPepper); err != nil {
		t.Fatalf("seeding secret key: %v", err)
	}
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_00000000000000000000000000000003", testApplication, liveSecretKey, cfg.APIKeyPepper); err != nil {
		t.Fatalf("seeding live secret key: %v", err)
	}

	return &testEnv{
		factory:      factory,
		cfg:          cfg,
		emails:       emails,
		texts:        texts,
		sandboxStore: sandboxStore,
		policyRepo:   policyRepo,
		authRepo:     authRepo,
		app:          app,
	}
}

// tokenFor returns the "token" query parameter from the newest message addressed
// to recipient.
//
// The sandbox is consulted first, because a request made through the publishable
// key acts in the test environment and its messages are captured rather than
// delivered. The recorder behind the sandbox is the fallback, which is where a
// send made on a bypassing context — one carrying no environment to judge —
// arrives.
//
// Returns false when neither holds a message for that recipient, so a caller can
// report that rather than asserting against an empty string.
func (e *testEnv) tokenFor(t *testing.T, recipient string) (string, bool) {
	t.Helper()

	ctx := privacy.NewContext(context.Background(), testTenant, "", testEnvironment)
	messages, _, err := e.sandboxStore.List(ctx, sandbox.Filter{Recipient: recipient})
	if err != nil {
		t.Fatalf("reading the sandbox inbox for %s: %v", recipient, err)
	}

	// List is newest first, so the first entry is the message a flow just
	// triggered.
	for _, m := range messages {
		if link, ok := m.Metadata["link"].(string); ok {
			if token, ok := tokenFromBody(link); ok {
				return token, true
			}
		}
		if token, ok := tokenFromBody(m.Body); ok {
			return token, true
		}
	}

	return e.emails.tokenFor(recipient)
}

// linkFor returns the whole emailed URL from the newest message addressed to
// recipient, so a test can assert on the origin a link points at rather than only
// on the token it carries.
//
// It reads the same two places tokenFor reads, in the same order and for the same
// reasons: the sandbox holds messages captured on the request path, the recorder
// behind it holds those sent on a bypassing context.
func (e *testEnv) linkFor(t *testing.T, recipient string) (string, bool) {
	t.Helper()

	ctx := privacy.NewContext(context.Background(), testTenant, "", testEnvironment)
	messages, _, err := e.sandboxStore.List(ctx, sandbox.Filter{Recipient: recipient})
	if err != nil {
		t.Fatalf("reading the sandbox inbox for %s: %v", recipient, err)
	}

	for _, m := range messages {
		if link, ok := m.Metadata["link"].(string); ok {
			if found, ok := linkFromBody(link); ok {
				return found, true
			}
		}
		if found, ok := linkFromBody(m.Body); ok {
			return found, true
		}
	}

	// messagesTo is oldest first, so it is walked backwards to keep "newest wins"
	// consistent with the sandbox above.
	recorded := e.emails.messagesTo(recipient)
	for i := len(recorded) - 1; i >= 0; i-- {
		body := recorded[i].html
		if body == "" {
			body = recorded[i].text
		}
		if found, ok := linkFromBody(body); ok {
			return found, true
		}
	}

	return "", false
}

// bypassContext returns a context that skips the privacy interceptor's tenant
// and environment filtering, for the direct database reads and writes a test
// performs to set up or inspect state.
func (e *testEnv) bypassContext() context.Context {
	return privacy.NewBypassContext(context.Background())
}

// response is a decoded HTTP reply from the engine.
type response struct {
	status int
	body   []byte
	// headers is the reply's header set, for the assertions that are about a
	// header rather than a body — a cache directive, for instance, which is part
	// of the contract of a response served to many tenants from one URL.
	headers http.Header
	cookies []*http.Cookie
}

// json decodes the response body into out, failing the test when the body is
// not the JSON shape the caller expected.
func (r response) json(t *testing.T, out any) {
	t.Helper()
	if err := json.Unmarshal(r.body, out); err != nil {
		t.Fatalf("decoding response body %q: %v", string(r.body), err)
	}
}

// cookie returns the named cookie from the response, or nil when absent.
func (r response) cookie(name string) *http.Cookie {
	for _, c := range r.cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// do sends a request to the in-process app and reads the whole reply.
//
// payload is marshalled as a JSON body when non-nil. Every request carries the
// publishable key, since all client routes sit behind that middleware. Extra
// headers and cookies are applied by the optional decorate callback.
//
// A transport-level failure fails the test immediately: it means the app could
// not be driven at all, so no assertion about the reply would be meaningful.
func (e *testEnv) do(t *testing.T, method, path string, payload any, decorate ...func(*http.Request)) response {
	t.Helper()

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("encoding request payload: %v", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, path, body)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authn-Publishable-Key", publishableKey)
	for _, d := range decorate {
		d(req)
	}

	resp, err := e.app.Test(req, requestTimeoutMillis)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s %s response: %v", method, path, err)
	}

	return response{status: resp.StatusCode, body: raw, headers: resp.Header, cookies: resp.Cookies()}
}

// signUp registers a user and returns the signup reply.
func (e *testEnv) signUp(t *testing.T, emailAddr, password, name string) response {
	t.Helper()
	return e.do(t, http.MethodPost, "/v1/client/auth/signup", map[string]string{
		"email":       emailAddr,
		"password":    password,
		"name":        name,
		"tenant_id":   testTenant,
		"environment": testEnvironment,
	})
}

// login authenticates a user, applying any extra request decoration such as a
// native-client header.
func (e *testEnv) login(t *testing.T, emailAddr, password string, decorate ...func(*http.Request)) response {
	t.Helper()
	return e.do(t, http.MethodPost, "/v1/client/auth/login", map[string]string{
		"email":       emailAddr,
		"password":    password,
		"tenant_id":   testTenant,
		"environment": testEnvironment,
	}, decorate...)
}

// withCookie returns a decorator that attaches a cookie to a request.
func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

// withHeader returns a decorator that sets a header on a request.
func withHeader(name, value string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(name, value) }
}
