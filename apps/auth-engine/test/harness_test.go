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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/settings"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// publishableKey is the API key the seeded test application accepts. It matches
// the demo key the seeder installs, so a request captured from local
// development can be replayed against this harness unchanged.
const publishableKey = "pk_test_demo12345678901234567890123456789012"

// testTenant and testEnvironment are the tenant and environment every request
// in this package is scoped to.
const (
	testTenant      = "tnt_00000000000000000000000000000001"
	testEnvironment = "test"
)

// requestTimeoutMillis bounds a single in-process request. It is far above any
// healthy response time because Argon2id password hashing deliberately costs
// hundreds of milliseconds, and signup performs one on the request path.
const requestTimeoutMillis = 30_000

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

// testEnv is one in-process engine instance under test.
type testEnv struct {
	factory    *clientfactory.ClientFactory
	cfg        *config.Config
	emails     *captureEmailProvider
	policyRepo *policy.Repository
	authRepo   *auth.Repository
	app        *fiber.App
}

// newTestEnv builds a wired engine: a private in-memory schema, a seeded
// tenant, application and publishable key, the capturing email provider, and
// the authentication and OAuth handlers mounted on a Fiber app.
//
// rateLimiter and resendLimiter may be nil, which leaves the matching routes
// unthrottled exactly as the real server does when rate limiting is off.
//
// The database is closed automatically when the test finishes.
func newTestEnv(t *testing.T, rateLimiter, resendLimiter *ratelimit.Limiter) *testEnv {
	t.Helper()

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

	cfg := &config.Config{
		Env:                config.EnvTest,
		DatabaseURL:        dsn,
		EncryptionKey:      "super_secret_32_byte_kms_encryption_key_authn_2026!",
		APIKeyPepper:       "super_secret_32_byte_api_key_pepper_authn_2026!",
		JWTSigningKeyPath:  "./keys/rsa_private.pem",
		EmailDriver:        "noop",
		RateLimitEnabled:   rateLimiter != nil,
		SessionGracePeriod: sessionGracePeriod,
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    720 * time.Hour,
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeyService := apikey.NewService(apiKeyRepo, cfg.APIKeyPepper)
	pkMiddleware := middleware.RequirePublishableKey(apiKeyService)

	policyRepo := policy.NewRepository(factory)
	emails := &captureEmailProvider{}
	var emailProvider email.EmailProvider = emails

	authRepo := auth.NewRepository(factory)
	authService := auth.NewService(authRepo, cfg, emailProvider)

	// The resolver is attached with a nil cache, so every read goes to the
	// database. That matches the server's degraded path and keeps a test from
	// asserting against a value another test left in a shared cache.
	settingsResolver := settings.NewResolver(factory, policyRepo, nil, 0)
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

	ctx := privacy.NewBypassContext(context.Background())
	if err := authRepo.EnsureTenantExists(ctx, testTenant); err != nil {
		t.Fatalf("seeding tenant: %v", err)
	}
	if err := authRepo.EnsureDefaultApplicationExists(ctx, "app_00000000000000000000000000000001", testTenant, []string{"http://localhost:3000/callback"}); err != nil {
		t.Fatalf("seeding application: %v", err)
	}
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_00000000000000000000000000000001", "app_00000000000000000000000000000001", publishableKey, cfg.APIKeyPepper); err != nil {
		t.Fatalf("seeding API key: %v", err)
	}

	return &testEnv{
		factory:    factory,
		cfg:        cfg,
		emails:     emails,
		policyRepo: policyRepo,
		authRepo:   authRepo,
		app:        app,
	}
}

// bypassContext returns a context that skips the privacy interceptor's tenant
// and environment filtering, for the direct database reads and writes a test
// performs to set up or inspect state.
func (e *testEnv) bypassContext() context.Context {
	return privacy.NewBypassContext(context.Background())
}

// response is a decoded HTTP reply from the engine.
type response struct {
	status  int
	body    []byte
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

	return response{status: resp.StatusCode, body: raw, cookies: resp.Cookies()}
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
