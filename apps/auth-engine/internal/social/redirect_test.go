/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/redirect_test.go
 * Tier: Social Identity Provider Layer / Tests
 *
 * Description: Covers the post-callback redirect, which carries a freshly
 *              issued access token. Three properties are pinned: the token
 *              travels in the URL fragment and never the query string, the
 *              destination's own query string survives intact with both
 *              components escaped, and the destination host must appear on the
 *              initiating application's registered allowlist.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

// The JWT shape matters: a real access token contains '.', '-' and '_', and may
// contain '+', '/' and '=' once anything base64-standard is involved. Every one
// of those either terminates or changes meaning inside a URL if unescaped.
const sampleJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c3JfYWJjIn0.s1g-n_a+t/u=re"

// TestBuildPostCallbackRedirect_TokenIsNotInQueryString pins the token to the
// fragment. A query parameter would be written to browser history, server and
// proxy access logs, and the Referer of any cross-origin subresource.
func TestBuildPostCallbackRedirect_TokenIsNotInQueryString(t *testing.T) {
	got, err := buildPostCallbackRedirect("https://app.example.com/cb", sampleJWT)
	if err != nil {
		t.Fatalf("buildPostCallbackRedirect: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result %q is not a parseable URL: %v", got, err)
	}

	if u.Query().Get("access_token") != "" {
		t.Errorf("access_token present in query string of %q — it must live in the fragment", got)
	}
	if u.RawQuery != "" {
		t.Errorf("RawQuery = %q, want empty (no query on a base without one)", u.RawQuery)
	}

	frag, err := url.ParseQuery(u.EscapedFragment())
	if err != nil {
		t.Fatalf("fragment %q is not parseable: %v", u.EscapedFragment(), err)
	}
	if got := frag.Get("access_token"); got != sampleJWT {
		t.Errorf("fragment access_token = %q, want %q", got, sampleJWT)
	}
	if got := frag.Get("token_type"); got != "Bearer" {
		t.Errorf("fragment token_type = %q, want Bearer", got)
	}
}

// TestBuildPostCallbackRedirect_PreservesExistingQuery pins that a destination
// which already carries a query string keeps it unchanged. Concatenating would
// emit a second "?" and fold the token into the preceding parameter's value.
func TestBuildPostCallbackRedirect_PreservesExistingQuery(t *testing.T) {
	base := "https://app.example.com/cb?tenant=acme&next=%2Fdashboard"

	got, err := buildPostCallbackRedirect(base, sampleJWT)
	if err != nil {
		t.Fatalf("buildPostCallbackRedirect: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result %q is not a parseable URL: %v", got, err)
	}

	q := u.Query()
	if q.Get("tenant") != "acme" {
		t.Errorf("tenant = %q, want acme (pre-existing query param was corrupted)", q.Get("tenant"))
	}
	if q.Get("next") != "/dashboard" {
		t.Errorf("next = %q, want /dashboard", q.Get("next"))
	}
	if len(q) != 2 {
		t.Errorf("query has %d params (%v), want exactly the 2 the base carried", len(q), q)
	}
	if q.Get("access_token") != "" {
		t.Errorf("access_token leaked into the query string of %q", got)
	}

	frag, err := url.ParseQuery(u.EscapedFragment())
	if err != nil {
		t.Fatalf("fragment %q is not parseable: %v", u.EscapedFragment(), err)
	}
	if got := frag.Get("access_token"); got != sampleJWT {
		t.Errorf("fragment access_token = %q, want %q — token must survive intact", got, sampleJWT)
	}
}

// TestBuildPostCallbackRedirect_EscapesToken guards the double-escaping trap:
// assigning to url.URL.Fragment makes String() re-escape the already-encoded
// Values.Encode() output, which would hand the client a mangled token.
func TestBuildPostCallbackRedirect_EscapesToken(t *testing.T) {
	hostile := "a+b/c=d%e&f=g#h ?i"

	got, err := buildPostCallbackRedirect("https://app.example.com/cb?x=1", hostile)
	if err != nil {
		t.Fatalf("buildPostCallbackRedirect: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result %q is not a parseable URL: %v", got, err)
	}
	if u.Query().Get("x") != "1" {
		t.Errorf("base query lost: x = %q, want 1", u.Query().Get("x"))
	}

	frag, err := url.ParseQuery(u.EscapedFragment())
	if err != nil {
		t.Fatalf("fragment %q is not parseable: %v", u.EscapedFragment(), err)
	}
	if got := frag.Get("access_token"); got != hostile {
		t.Errorf("token round-trip = %q, want %q", got, hostile)
	}
}

func TestBuildPostCallbackRedirect_DropsExistingFragment(t *testing.T) {
	got, err := buildPostCallbackRedirect("https://app.example.com/cb#stale=1", sampleJWT)
	if err != nil {
		t.Fatalf("buildPostCallbackRedirect: %v", err)
	}

	u, _ := url.Parse(got)
	frag, err := url.ParseQuery(u.EscapedFragment())
	if err != nil {
		t.Fatalf("fragment %q is not parseable: %v", u.EscapedFragment(), err)
	}
	if frag.Get("stale") != "" {
		t.Errorf("stale fragment survived in %q — the fragment slot must be ours alone", got)
	}
	if frag.Get("access_token") != sampleJWT {
		t.Errorf("access_token = %q, want %q", frag.Get("access_token"), sampleJWT)
	}
}

// --- post-callback destination allowlist ---

func setupRedirectTestService(t *testing.T) (*Service, context.Context) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "social_redirect_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	dbPath := filepath.Join(tmpDir, "test.db") + "?_fk=1"
	factory, err := clientfactory.NewClientFactory("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to initialize client factory: %v", err)
	}
	t.Cleanup(func() { factory.Close() })

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "tnt_test", "test")
	if err := client.Schema.Create(sysCtx); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	if _, err := client.Tenant.Create().
		SetID("tnt_test").
		SetName("Test Tenant").
		SetSlug("test-tenant").
		Save(sysCtx); err != nil {
		t.Fatalf("failed seeding tenant: %v", err)
	}

	if _, err := client.Application.Create().
		SetID("app_test").
		SetTenantID("tnt_test").
		SetName("Test App").
		SetExactRedirectUris([]string{"https://app.example.com/callback"}).
		Save(sysCtx); err != nil {
		t.Fatalf("failed seeding application: %v", err)
	}

	repo := NewRepository(factory, "0123456789abcdef0123456789abcdef")
	svc := NewService(repo, &config.Config{}, session.NewRepository(factory))

	return svc, sysCtx
}

func TestValidatePostCallbackRedirect(t *testing.T) {
	svc, ctx := setupRedirectTestService(t)

	cases := []struct {
		name    string
		target  string
		appID   string
		allowed bool
	}{
		{"empty target is a no-op", "", "app_test", true},
		{"exact registered match", "https://app.example.com/callback", "app_test", true},
		{"same origin, different path", "https://app.example.com/dashboard", "app_test", true},
		{"same origin with query", "https://app.example.com/dashboard?tenant=acme", "app_test", true},

		// A publishable key is public by design, so anyone able to start a social
		// login can put an arbitrary host here. The allowlist is what stops it.
		{"attacker host", "https://evil.example.net/steal", "app_test", false},
		{"attacker subdomain", "https://app.example.com.evil.net/steal", "app_test", false},
		{"scheme downgrade to http", "http://app.example.com/callback", "app_test", false},
		{"port mismatch", "https://app.example.com:8443/callback", "app_test", false},

		// Non-absolute / non-http(s) inputs parse without error in net/url, so
		// they need an explicit rejection rather than a parse check.
		{"javascript scheme", "javascript:alert(document.cookie)", "app_test", false},
		{"scheme-relative host", "//evil.example.net/steal", "app_test", false},
		{"path-relative", "/dashboard", "app_test", false},
		{"data scheme", "data:text/html,<script>alert(1)</script>", "app_test", false},

		// Fail-closed when there is no allowlist to satisfy.
		{"no application id", "https://app.example.com/callback", "", false},
		{"unregistered application id", "https://app.example.com/callback", "app_missing", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.validatePostCallbackRedirect(ctx, "tnt_test", "test", tc.appID, tc.target)
			if tc.allowed && err != nil {
				t.Errorf("target %q was rejected (%v), want allowed", tc.target, err)
			}
			if !tc.allowed {
				if err == nil {
					t.Errorf("target %q was ALLOWED — open redirect forwarding a live access token", tc.target)
				} else if !errors.Is(err, ErrRedirectNotAllowed) {
					t.Errorf("target %q rejected with %v, want ErrRedirectNotAllowed", tc.target, err)
				}
			}
		})
	}
}

// TestValidatePostCallbackRedirect_EmptyAllowlistFailsClosed pins the behaviour
// for an application registered without any exact_redirect_uris: no entry can
// match, so nothing is authorized.
func TestValidatePostCallbackRedirect_EmptyAllowlistFailsClosed(t *testing.T) {
	svc, ctx := setupRedirectTestService(t)

	client := svc.repo.factory.GetClient(ctx, "tnt_test", "test")
	if _, err := client.Application.Create().
		SetID("app_noallow").
		SetTenantID("tnt_test").
		SetName("No Allowlist App").
		Save(ctx); err != nil {
		t.Fatalf("failed seeding application: %v", err)
	}

	err := svc.validatePostCallbackRedirect(ctx, "tnt_test", "test", "app_noallow", "https://app.example.com/callback")
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Errorf("err = %v, want ErrRedirectNotAllowed for an application with no registered redirect URIs", err)
	}
}

// TestValidatePostCallbackRedirect_UnderRealPrivacyInterceptor proves the
// allowlist query works under production conditions. The setup tests above use a
// bypass context to seed rows; validatePostCallbackRedirect itself runs against
// the request context pkMiddleware installs (privacy.NewContext — see
// internal/middleware/publishable_key.go), where the interceptor filters every
// ApplicationQuery by tenant and environment and fails closed if either is
// missing. A regression here would surface as a 500 on every social login.
func TestValidatePostCallbackRedirect_UnderRealPrivacyInterceptor(t *testing.T) {
	svc, _ := setupRedirectTestService(t)

	client := svc.repo.factory.GetClient(context.Background(), "tnt_test", "test")
	privacy.AttachPrivacyInterceptors(client)

	reqCtx := privacy.NewContext(context.Background(), "tnt_test", "app_test", "test")

	if err := svc.validatePostCallbackRedirect(reqCtx, "tnt_test", "test", "app_test", "https://app.example.com/dashboard"); err != nil {
		t.Fatalf("valid same-origin target rejected under privacy interceptor: %v", err)
	}
	if err := svc.validatePostCallbackRedirect(reqCtx, "tnt_test", "test", "app_test", "https://evil.example.net/steal"); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("attacker host: err = %v, want ErrRedirectNotAllowed", err)
	}
}
