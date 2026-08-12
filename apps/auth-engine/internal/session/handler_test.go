/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/handler_test.go
 * Tier: HTTP Delivery Layer / Tests
 *
 * Description: Tests for caller resolution on the session-management routes —
 *              that a cookie-authenticated browser session is recognised, that
 *              the header path still works, and that an unsigned or tampered
 *              token is refused rather than trusted.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

const testSigningSecret = "test-signing-secret-value-32-bytes!!"

// newResolverHandler returns a Handler wired with only what caller resolution
// needs: the signing secret. No database is touched, because resolution happens
// before any repository call.
func newResolverHandler() *Handler {
	return &Handler{svc: &Service{cfg: &config.Config{EncryptionKey: testSigningSecret}}}
}

// newCookie builds a request cookie carrying an access token.
func newCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value}
}

// TestGetUserIDAndSessionID_CookieAuthenticatedSession pins the credential
// shapes this route accepts.
//
// A browser holds its session in a cookie, which is the form RequireClientAuth
// accepts first. Resolving from the Authorization header alone would leave such
// a client unable to list or revoke its own sessions.
func TestGetUserIDAndSessionID_CookieAuthenticatedSession(t *testing.T) {
	token, err := jwtpkg.IssueAccessTokenWithSession(
		"usr_cookie", "tnt_00000000000000000000000000000001", "test",
		"cookie@example.com", "Cookie User", "", "ses_cookie", testSigningSecret, 15*time.Minute)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}

	h := newResolverHandler()

	cases := []struct {
		name       string
		cookieName string
	}{
		{"canonical cookie", "authn_access_token"},
		{"legacy cookie", "access_token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			var gotUser, gotSession string
			app.Get("/probe", func(c *fiber.Ctx) error {
				gotUser, gotSession = h.getUserIDAndSessionID(c)
				return c.SendStatus(fiber.StatusOK)
			})

			req := httptest.NewRequest("GET", "/probe", nil)
			req.AddCookie((newCookie(tc.cookieName, token)))
			if _, err := app.Test(req); err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			if gotUser != "usr_cookie" {
				t.Errorf("userID from %s = %q, want %q", tc.cookieName, gotUser, "usr_cookie")
			}
			if gotSession != "ses_cookie" {
				t.Errorf("sessionID from %s = %q, want %q", tc.cookieName, gotSession, "ses_cookie")
			}
		})
	}
}

// TestGetUserIDAndSessionID_BearerHeaderStillWorks pins the path that already
// worked, so sharing the extractor cannot have traded one credential shape for
// another.
func TestGetUserIDAndSessionID_BearerHeaderStillWorks(t *testing.T) {
	token, err := jwtpkg.IssueAccessTokenWithSession(
		"usr_hdr", "tnt_00000000000000000000000000000001", "test",
		"hdr@example.com", "Header User", "", "ses_hdr", testSigningSecret, 15*time.Minute)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}

	h := newResolverHandler()
	app := fiber.New()
	var gotUser, gotSession string
	app.Get("/probe", func(c *fiber.Ctx) error {
		gotUser, gotSession = h.getUserIDAndSessionID(c)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := app.Test(req); err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if gotUser != "usr_hdr" || gotSession != "ses_hdr" {
		t.Errorf("got (%q, %q), want (usr_hdr, ses_hdr)", gotUser, gotSession)
	}
}

// TestGetUserIDAndSessionID_RejectsUntrustedTokens confirms resolution is a
// verification and not a decode: every one of these must yield no identity, so
// the calling handlers answer 401.
func TestGetUserIDAndSessionID_RejectsUntrustedTokens(t *testing.T) {
	valid, err := jwtpkg.IssueAccessTokenWithSession(
		"usr_real", "tnt_00000000000000000000000000000001", "test",
		"real@example.com", "Real User", "", "ses_real", testSigningSecret, 15*time.Minute)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}

	forged, err := jwtpkg.IssueAccessTokenWithSession(
		"usr_attacker", "tnt_00000000000000000000000000000001", "test",
		"attacker@example.com", "Attacker", "", "ses_attacker", "a-completely-different-secret-value!!", 15*time.Minute)
	if err != nil {
		t.Fatalf("issuing forged token: %v", err)
	}

	cases := []struct {
		name  string
		token string
	}{
		{"signed with the wrong secret", forged},
		{"tampered payload", valid[:len(valid)-6] + "AAAAAA"},
		{"not a token at all", "garbage"},
		{"empty", ""},
	}

	h := newResolverHandler()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			var gotUser, gotSession string
			app.Get("/probe", func(c *fiber.Ctx) error {
				gotUser, gotSession = h.getUserIDAndSessionID(c)
				return c.SendStatus(fiber.StatusOK)
			})

			req := httptest.NewRequest("GET", "/probe", nil)
			if tc.token != "" {
				req.AddCookie((newCookie("authn_access_token", tc.token)))
			}
			if _, err := app.Test(req); err != nil {
				t.Fatalf("app.Test: %v", err)
			}

			if gotUser != "" || gotSession != "" {
				t.Errorf("untrusted token %q yielded identity (%q, %q); must yield none",
					tc.name, gotUser, gotSession)
			}
		})
	}
}

// TestGetUserIDAndSessionID_LocalsWinOverToken confirms the middleware-supplied
// locals take precedence, so the token fallback cannot override an identity the
// authenticating middleware already established.
func TestGetUserIDAndSessionID_LocalsWinOverToken(t *testing.T) {
	token, err := jwtpkg.IssueAccessTokenWithSession(
		"usr_from_token", "tnt_00000000000000000000000000000001", "test",
		"t@example.com", "T", "", "ses_from_token", testSigningSecret, 15*time.Minute)
	if err != nil {
		t.Fatalf("issuing token: %v", err)
	}

	h := newResolverHandler()
	app := fiber.New()
	var gotUser, gotSession string
	app.Get("/probe", func(c *fiber.Ctx) error {
		c.Locals("user_id", "usr_from_locals")
		c.Locals("session_id", "ses_from_locals")
		gotUser, gotSession = h.getUserIDAndSessionID(c)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/probe", nil)
	req.AddCookie((newCookie("authn_access_token", token)))
	if _, err := app.Test(req); err != nil {
		t.Fatalf("app.Test: %v", err)
	}

	if gotUser != "usr_from_locals" || gotSession != "ses_from_locals" {
		t.Errorf("got (%q, %q), want locals to win", gotUser, gotSession)
	}
}
