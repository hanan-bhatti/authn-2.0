/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/httperr/httperr_test.go
 * Tier: HTTP Transport Layer / Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package httperr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func doRequest(t *testing.T, handler fiber.Handler) (int, map[string]any, string) {
	t.Helper()
	app := fiber.New()
	app.Get("/probe", handler)

	resp, err := app.Test(httptest.NewRequest("GET", "/probe", nil), -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("body is not JSON (%q): %v", string(raw), err)
	}
	return resp.StatusCode, body, string(raw)
}

func TestEnvelopeShape(t *testing.T) {
	status, body, _ := doRequest(t, func(c *fiber.Ctx) error {
		return Unauthorized(c, CodeInvalidCredentials, "email or password is incorrect")
	})

	if status != fiber.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	if got := body["error"]; got != "email or password is incorrect" {
		t.Errorf("error = %v, want the human-readable prose", got)
	}
	if got := body["code"]; got != "invalid_credentials" {
		t.Errorf("code = %v, want invalid_credentials", got)
	}
	// The SDK reads exactly these two keys; anything else is dead weight and a
	// nested shape would break AuthnError.fromResponse.
	if len(body) != 2 {
		t.Errorf("envelope has %d keys (%v), want exactly error+code", len(body), body)
	}
}

// The security property that motivated the package: internal error text must
// never reach the client, no matter how it is wrapped.
func TestSendInternalDoesNotLeakErrorText(t *testing.T) {
	secret := "pq: relation \"users\" does not exist"
	wrapped := fmt.Errorf("loading account: %w", errors.New(secret))

	status, body, raw := doRequest(t, func(c *fiber.Ctx) error {
		return SendInternal(c, "auth.login", wrapped)
	})

	if status != fiber.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
	if strings.Contains(raw, secret) || strings.Contains(raw, "relation") {
		t.Errorf("internal error text leaked to client: %s", raw)
	}
	if strings.Contains(raw, "loading account") {
		t.Errorf("wrapper context leaked to client: %s", raw)
	}
	if body["code"] != "internal_error" {
		t.Errorf("code = %v, want internal_error", body["code"])
	}
	if body["error"] == "" {
		t.Error("error message must still be present and non-empty")
	}
}

func TestSendInternalTolerastesNilError(t *testing.T) {
	status, body, _ := doRequest(t, func(c *fiber.Ctx) error {
		return SendInternal(c, "auth.noop", nil)
	})
	if status != fiber.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
	if body["code"] != "internal_error" {
		t.Errorf("code = %v, want internal_error", body["code"])
	}
}

func TestStatusHelpers(t *testing.T) {
	cases := []struct {
		name    string
		handler fiber.Handler
		status  int
		code    string
	}{
		{"forbidden", func(c *fiber.Ctx) error {
			return Forbidden(c, CodeInsufficientScope, "nope")
		}, 403, "insufficient_permissions"},
		{"not found", func(c *fiber.Ctx) error {
			return NotFound(c, CodeNotFound, "nope")
		}, 404, "not_found"},
		{"conflict", func(c *fiber.Ctx) error {
			return Conflict(c, CodeAlreadyExists, "nope")
		}, 409, "already_exists"},
		{"unprocessable", func(c *fiber.Ctx) error {
			return UnprocessableEntity(c, CodeValidationFailed, "nope")
		}, 422, "validation_failed"},
		{"rate limited", func(c *fiber.Ctx) error {
			return TooManyRequests(c, CodeRateLimited, "nope")
		}, 429, "rate_limited"},
		{"invalid body", InvalidBody, 400, "invalid_request_body"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := doRequest(t, tc.handler)
			if status != tc.status {
				t.Errorf("status = %d, want %d", status, tc.status)
			}
			if body["code"] != tc.code {
				t.Errorf("code = %v, want %q", body["code"], tc.code)
			}
		})
	}
}
