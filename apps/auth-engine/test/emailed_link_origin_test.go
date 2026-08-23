//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/emailed_link_origin_test.go
 * Tier: Integration Tests / Emailed Link Landing
 *
 * Covers where an emailed link points. A recipient clicking one sends no headers
 * a browser can be told to add, so a link aimed at the engine either fails the
 * publishable-key guard or answers a top-level navigation with JSON — and for a
 * magic link that JSON is a working access token rendered into a browser window
 * and its history. Every emailed link must therefore open a page.
 *
 * The other suites read the token out of a message and post it themselves, which
 * passes no matter what origin the link carried. These assertions are the only
 * ones that would catch a link that authenticates correctly but cannot be clicked.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// linkOriginFor triggers nothing itself; it reads the newest emailed link for an
// address and fails the test when none was sent.
func linkOriginFor(t *testing.T, env *testEnv, address string) string {
	t.Helper()

	link, ok := env.linkFor(t, address)
	if !ok {
		t.Fatalf("no email carrying a link was sent to %s", address)
	}
	return link
}

// TestVerificationLinkOpensTheFrontend checks that the signup verification link
// points at the configured frontend origin and not at the API.
func TestVerificationLinkOpensTheFrontend(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "link_origin_verify@example.com"
	if resp := env.signUp(t, address, "LinkOrigin!Pass123", "Link Origin"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	link := linkOriginFor(t, env, address)

	want := testFrontendBaseURL + "/verify-email?token="
	if !strings.HasPrefix(link, want) {
		t.Errorf("verification link is %q, want a URL starting %q", link, want)
	}
	if strings.Contains(link, env.cfg.AppBaseURL) {
		t.Errorf("verification link %q points at the API origin, where a click has no publishable key to present", link)
	}
}

// TestMagicLinkOpensTheFrontend checks the same for the passwordless link, which
// is the one where the cost of pointing at the API is highest: the verify route
// returns an access token in its body.
func TestMagicLinkOpensTheFrontend(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "link_origin_magic@example.com"
	requestMagicLink(t, env, address)

	link := linkOriginFor(t, env, address)

	want := testFrontendBaseURL + "/magic-link?token="
	if !strings.HasPrefix(link, want) {
		t.Errorf("magic link is %q, want a URL starting %q", link, want)
	}
	if strings.Contains(link, env.cfg.AppBaseURL) {
		t.Errorf("magic link %q points at the API, which would answer a top-level navigation with an access token in the body", link)
	}
}

// TestApplicationFrontendBaseURLOverridesTheDeployment checks that an origin
// stored on the application row wins over the deployment-wide default.
//
// This is the case a deployment-wide setting alone cannot serve: one tenant may
// run several applications on separate domains, and a link that opens the wrong
// one leaves the recipient signed in somewhere they were not trying to reach.
func TestApplicationFrontendBaseURLOverridesTheDeployment(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	ctx := env.bypassContext()
	if _, err := env.factory.GetClient(ctx, testTenant, testEnvironment).
		Application.UpdateOneID(testApplication).
		SetFrontendBaseURL(testApplicationFrontendBaseURL).
		Save(ctx); err != nil {
		t.Fatalf("setting frontend_base_url on %s: %v", testApplication, err)
	}

	const address = "link_origin_override@example.com"
	requestMagicLink(t, env, address)

	link := linkOriginFor(t, env, address)

	want := testApplicationFrontendBaseURL + "/magic-link?token="
	if !strings.HasPrefix(link, want) {
		t.Errorf("magic link is %q, want the application's own origin: %q", link, want)
	}
	if strings.HasPrefix(link, testFrontendBaseURL) {
		t.Errorf("magic link %q used the deployment default though the application configured %q",
			link, testApplicationFrontendBaseURL)
	}
}

// TestMagicLinkVerifyIsNotReachableByNavigation checks that the route the emailed
// link used to point at no longer issues a session.
//
// It answered a browser navigation with an access token in the response body,
// which lands in history and in the Referer of every link on the page that
// rendered it. The frontend posts the token instead.
//
// The assertion is that no session comes back, not that the status is 404. The GET
// registration is gone, but two handlers attach a session requirement to the whole
// /v1/client prefix (see rbac and impersonation), and Fiber runs prefix middleware
// even where no route matches — so the observed answer is 401 from that guard.
// Pinning 404 would couple this test to which middleware wins that race.
func TestMagicLinkVerifyIsNotReachableByNavigation(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "link_origin_no_get@example.com"
	requestMagicLink(t, env, address)

	token, ok := env.tokenFor(t, address)
	if !ok {
		t.Fatalf("no magic-link email carrying a token was sent to %s", address)
	}

	resp := env.do(t, http.MethodGet, "/v1/client/auth/magic-link/verify?token="+token, nil)
	if resp.status == http.StatusOK {
		t.Fatalf("GET magic-link/verify answered 200; a navigable route puts an access token in the body: %s", resp.body)
	}
	// Decoded rather than substring-matched: the refusal's own message names the
	// Authorization header and so contains the words "access_token".
	var issued struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(resp.body, &issued)
	if issued.AccessToken != "" {
		t.Fatalf("GET magic-link/verify returned an access token at status %d: %s", resp.status, resp.body)
	}

	// The token is untouched by the refused GET, so the POST the frontend makes
	// still works. A route removal that consumed the token on the way out would
	// leave the user with a dead link.
	if post := env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify",
		map[string]string{"token": token}); post.status != http.StatusOK {
		t.Fatalf("POST magic-link/verify after the refused GET: got status %d, want 200; body %s", post.status, post.body)
	}
}

// TestEmailedLandingsRejectTheKeyInTheQueryString checks that the routes the
// frontend calls no longer accept a publishable key as ?pk=.
//
// They accepted one while the emailed link pointed at them directly. Now that the
// link opens a page, the only caller is the frontend, which holds a key and sets
// the header — so a key in a query string is one needlessly written into browser
// history and access logs.
func TestEmailedLandingsRejectTheKeyInTheQueryString(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "link_origin_query_key@example.com"
	if resp := env.signUp(t, address, "LinkOrigin!Pass123", "Query Key"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	token, ok := env.tokenFor(t, address)
	if !ok {
		t.Fatalf("no verification email carrying a token was sent to %s", address)
	}

	withoutHeader := func(req *http.Request) { req.Header.Del("X-Authn-Publishable-Key") }

	resp := env.do(t, http.MethodGet,
		"/v1/client/auth/verify-email?token="+token+"&pk="+publishableKey, nil, withoutHeader)
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("verify-email with the key only in the query: got status %d, want 401; body %s", resp.status, resp.body)
	}

	// The same request with the key in the header is the call the frontend makes,
	// and it must still verify the address.
	if header := env.do(t, http.MethodGet, "/v1/client/auth/verify-email?token="+token, nil); header.status != http.StatusOK {
		t.Fatalf("verify-email with the key in the header: got status %d, want 200; body %s", header.status, header.body)
	}
}
