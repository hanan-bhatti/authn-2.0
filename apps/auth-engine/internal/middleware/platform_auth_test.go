/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/platform_auth_test.go
 * Tier: Security Middleware Unit Tests
 *
 * The control-plane guard is the only thing standing between a self-serve signup
 * and the ability to mint tenants and API keys, and every one of its refusals is
 * a distinct security property. Each is driven separately here so a regression
 * names which one broke.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	platformSecret   = "test_encryption_key_32_bytes_12345"
	platformTenant   = "tnt_platform000000000000000000001"
	customerTenant   = "tnt_customer00000000000000000001"
	platformUserID   = "usr_operator1"
	platformUserMail = "operator@example.com"
)

// fakeSecretKey and fakePublishableKey stand in for API keys of either kind.
//
// Only the prefix carries meaning here — it is the whole of what the guard reads
// — so the bodies are hyphenated, which the real format never is. Secret scanners
// match anything shaped like sk_live_ followed by a run of alphanumerics,
// fabricated literals included, and a push blocked on a test fixture is a worse
// outcome than a fixture that reads as obviously invented.
const (
	fakeSecretKey      = "sk_live_fixture-not-a-real-secret-key"
	fakePublishableKey = "pk_live_fixture-not-a-real-publishable-key"
)

// stubAccountLookup is a PlatformAccountLookup with a fixed answer.
//
// It also records the context it was called with, which is what lets a test
// assert that the guard installs the platform scope *before* consulting it: a
// lookup running on an unscoped context would read across tenants.
type stubAccountLookup struct {
	verified bool
	found    bool
	err      error

	calledWith context.Context
	callCount  int
}

func (s *stubAccountLookup) EmailVerified(ctx context.Context, _ string) (bool, bool, error) {
	s.calledWith = ctx
	s.callCount++
	return s.verified, s.found, s.err
}

// verifiedLookup is the ordinary case: the account exists and is verified.
func verifiedLookup() *stubAccountLookup {
	return &stubAccountLookup{verified: true, found: true}
}

// platformApp mounts a probe route behind the guard under test.
//
// The probe echoes what the guard put on the request locals, so a test can
// assert on the resolved identity rather than only on the status code.
func platformApp(t *testing.T, platformTenantID string, lookup middleware.PlatformAccountLookup) *fiber.App {
	t.Helper()

	app := fiber.New()
	app.Use(middleware.RequirePlatformAuth(platformSecret, platformTenantID, nil, lookup))
	app.Post("/v1/platform/tenants", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"tenant_id":        middleware.GetTenantID(c),
			"platform_user_id": middleware.PlatformUserID(c),
			"environment":      middleware.GetEnvironment(c),
		})
	})
	return app
}

// platformToken issues an ordinary access token for the given tenant.
func platformToken(t *testing.T, tenantID string) string {
	t.Helper()
	tok, err := jwtpkg.IssueAccessToken(platformUserID, tenantID, "live", platformUserMail,
		"Operator", "user", platformSecret, 15*time.Minute)
	require.NoError(t, err)
	return tok
}

// expiredPlatformToken hand-signs a well-formed token whose exp is in the past.
//
// The issuing helpers cannot produce one: a non-positive ttl is read as "no
// lifetime configured" and replaced with the default, so asking them for a
// negative duration yields a perfectly valid token. Signing the payload here is
// the only way to present the guard with a session that has genuinely lapsed, as
// distinct from one that was forged.
func expiredPlatformToken(t *testing.T, tenantID string) string {
	t.Helper()

	expiry := time.Now().UTC().Add(-1 * time.Hour).Unix()
	payload := fmt.Sprintf(
		`{"sub":%q,"tenant_id":%q,"environment":"live","email":%q,"iss":"authn","iat":%d,"exp":%d,"jti":"jti_expired"}`,
		platformUserID, tenantID, platformUserMail, expiry, expiry)

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString([]byte(payload))

	mac := hmac.New(sha256.New, []byte(platformSecret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil))
}

// post drives the probe route and returns the reply.
func post(t *testing.T, app *fiber.App, decorate ...func(*http.Request)) *http.Response {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/platform/tenants", nil)
	for _, d := range decorate {
		d(req)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	return resp
}

// bearer returns a decorator setting the Authorization header.
func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

// TestPlatformAuthAdmitsVerifiedPlatformMember covers the success path.
//
// The assertions go past the status code to the resolved identity, because a
// guard that admits the right caller while resolving the wrong tenant would send
// a handler's writes into somebody else's data.
func TestPlatformAuthAdmitsVerifiedPlatformMember(t *testing.T) {
	lookup := verifiedLookup()
	app := platformApp(t, platformTenant, lookup)

	resp := post(t, app, bearer(platformToken(t, platformTenant)))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		TenantID       string `json:"tenant_id"`
		PlatformUserID string `json:"platform_user_id"`
		Environment    string `json:"environment"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, platformTenant, body.TenantID,
		"the handler must see the platform tenant, which is what scopes its writes")
	assert.Equal(t, platformUserID, body.PlatformUserID,
		"ownership is attributed to this value, so it must be the token's subject")
	assert.Equal(t, "live", body.Environment)

	// The scope must be installed before the account lookup runs, or the lookup
	// reads users without a tenant filter.
	require.Equal(t, 1, lookup.callCount)
	p, ok := privacy.FromContext(lookup.calledWith)
	require.True(t, ok, "the account lookup ran on a context carrying no privacy scope")
	assert.Equal(t, platformTenant, p.TenantID)
	assert.False(t, p.Bypass, "the lookup must not run under a privacy bypass")
}

// TestPlatformAuthAcceptsCookieDeliveredToken pins cookie support.
//
// The console is a browser application, so its session normally arrives as a
// cookie rather than an Authorization header. A guard that read only the header
// would refuse every real console request.
func TestPlatformAuthAcceptsCookieDeliveredToken(t *testing.T) {
	app := platformApp(t, platformTenant, verifiedLookup())

	for _, name := range []string{"authn_access_token", "access_token"} {
		resp := post(t, app, func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: name, Value: platformToken(t, platformTenant)})
		})
		assert.Equal(t, http.StatusOK, resp.StatusCode, "cookie %s", name)
	}
}

// TestPlatformAuthHiddenWithoutPlatformTenant covers the OSS deployment.
//
// A deployment that hosts no control plane should not disclose that these routes
// exist. Registration is skipped in that case, so this asserts the guard's own
// backstop for a miswiring — and it must be 404, not 401 or 403, because those
// would confirm the surface is there.
func TestPlatformAuthHiddenWithoutPlatformTenant(t *testing.T) {
	app := platformApp(t, "", verifiedLookup())

	resp := post(t, app, bearer(platformToken(t, platformTenant)))
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "not_found", errorCode(t, resp))
}

// TestPlatformAuthRefusesEveryoneWithoutLookup covers the mandatory email check.
//
// The verified-email requirement is not a nicety: the platform tenant's
// publishable key is public, so anyone can sign up into it, and that check is the
// only barrier between an arbitrary address and a tenant-minting credential. A
// guard wired without the lookup must therefore admit nobody, rather than
// silently drop the requirement.
func TestPlatformAuthRefusesEveryoneWithoutLookup(t *testing.T) {
	app := platformApp(t, platformTenant, nil)

	resp := post(t, app, bearer(platformToken(t, platformTenant)))
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestPlatformAuthRejectsAPIKeys covers the JWT-only rule.
//
// A publishable key is public by design, and a secret key names a tenant rather
// than a person. Provisioning attributes ownership to a human, so neither
// credential can be allowed to authenticate here — including a secret key
// presented in its own header, where a guard reading only Authorization would
// never look at it.
//
// The assertions include the error code because the status alone cannot tell
// these refusals apart from an unparseable token: drop the prefix check and an
// sk_ still earns a 401, just from the JWT parser downstream. The distinction is
// worth holding onto twice over — the caller gets told to sign in instead of
// being handed "invalid token" for a credential that is perfectly valid
// elsewhere, and the key never reaches a verifier that a later refactor might
// make more forgiving.
func TestPlatformAuthRejectsAPIKeys(t *testing.T) {
	app := platformApp(t, platformTenant, verifiedLookup())

	cases := []struct {
		name     string
		decorate func(*http.Request)
	}{
		{"secret key header", func(r *http.Request) {
			r.Header.Set("X-Authn-Secret-Key", fakeSecretKey)
		}},
		{"secret key bearer", bearer(fakeSecretKey)},
		{"publishable key bearer", bearer(fakePublishableKey)},
		{"secret key header alongside a valid token", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+platformToken(t, platformTenant))
			r.Header.Set("X-Authn-Secret-Key", fakeSecretKey)
		}},
		{"secret key in the access token cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{
				Name:  "authn_access_token",
				Value: fakeSecretKey,
			})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(t, app, tc.decorate)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.Equal(t, "unauthorized", errorCode(t, resp),
				"the key must be refused as a key, not fall through to the token verifier")
		})
	}
}

// TestPlatformAuthRejectsMissingAndUnverifiableTokens covers the 401 boundary.
func TestPlatformAuthRejectsMissingAndUnverifiableTokens(t *testing.T) {
	app := platformApp(t, platformTenant, verifiedLookup())

	// No credential at all.
	resp := post(t, app)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Structurally a JWT, signed with a different secret.
	foreign, err := jwtpkg.IssueAccessToken(platformUserID, platformTenant, "live", platformUserMail,
		"Operator", "user", "an_entirely_different_signing_secret_x", 15*time.Minute)
	require.NoError(t, err)
	resp = post(t, app, bearer(foreign))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_token", errorCode(t, resp))

	// Not a JWT at all.
	resp = post(t, app, bearer("not-a-jwt"))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Expired: the signature verifies, the lifetime does not.
	resp = post(t, app, bearer(expiredPlatformToken(t, platformTenant)))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_token", errorCode(t, resp))
}

// TestPlatformAuthRejectsForeignTenant covers the tenant boundary.
//
// A customer's own end-user token is a perfectly valid JWT signed by this
// deployment. What disqualifies it is which tenant it belongs to — so this is the
// check that keeps the control plane from being reachable by every user of every
// hosted tenant.
func TestPlatformAuthRejectsForeignTenant(t *testing.T) {
	lookup := verifiedLookup()
	app := platformApp(t, platformTenant, lookup)

	resp := post(t, app, bearer(platformToken(t, customerTenant)))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "tenant_mismatch", errorCode(t, resp))
	assert.Zero(t, lookup.callCount,
		"a foreign token must be refused before its subject is looked up")
}

// TestPlatformAuthRejectsImpersonatedToken covers the impersonation boundary.
//
// An operator impersonating a customer holds a token that names the customer and
// is marked impersonated. Admitting it here would turn a read-only support
// session into a credential that provisions tenants owned by the person being
// supported.
func TestPlatformAuthRejectsImpersonatedToken(t *testing.T) {
	app := platformApp(t, platformTenant, verifiedLookup())

	impToken, err := jwtpkg.IssueImpersonationToken(platformUserID, platformTenant, "live",
		platformUserMail, "Operator", "user", "usr_admin99", "", 15*time.Minute, platformSecret)
	require.NoError(t, err)

	resp := post(t, app, bearer(impToken))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "impersonation_blocked", errorCode(t, resp))
}

// TestPlatformAuthRequiresVerifiedEmail covers the three lookup outcomes.
//
// They are distinct on purpose. An unverified address is a live session that has
// not finished signing up and is fixed by clicking a link; a missing account
// invalidates the session; a lookup failure is the server's problem. Collapsing
// them would send the caller after the wrong remedy — and returning 200 on the
// failure case would drop the check exactly when it cannot see.
func TestPlatformAuthRequiresVerifiedEmail(t *testing.T) {
	cases := []struct {
		name       string
		lookup     *stubAccountLookup
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unverified address",
			lookup:     &stubAccountLookup{verified: false, found: true},
			wantStatus: http.StatusForbidden,
			wantCode:   "email_verification_required",
		},
		{
			name:       "account no longer exists",
			lookup:     &stubAccountLookup{found: false},
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_token",
		},
		{
			name:       "lookup unavailable",
			lookup:     &stubAccountLookup{err: errors.New("database unreachable")},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "service_unavailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := platformApp(t, platformTenant, tc.lookup)
			resp := post(t, app, bearer(platformToken(t, platformTenant)))

			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			assert.Equal(t, tc.wantCode, errorCode(t, resp))
		})
	}
}

// TestPlatformUserIDAbsentWithoutGuard pins the accessor's behaviour off the
// guarded path.
//
// Handlers attribute tenant ownership to PlatformUserID. If it invented a value
// when no guard had run, a route mounted without the guard would record
// ownership against whatever that value happened to be, so the empty string is
// the only safe answer.
func TestPlatformUserIDAbsentWithoutGuard(t *testing.T) {
	app := fiber.New()
	app.Get("/probe", func(c *fiber.Ctx) error {
		return c.SendString(middleware.PlatformUserID(c))
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var buf [64]byte
	n, _ := resp.Body.Read(buf[:])
	assert.Equal(t, 0, n, "PlatformUserID must be empty when no guard resolved a caller")
}
