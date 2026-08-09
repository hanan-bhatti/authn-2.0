//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/ratelimit_test.go
 * Tier: Integration Tests / Rate Limiting Through the HTTP Stack
 *
 * Covers the two limiter behaviours that only appear once the limiter is
 * mounted on real routes: the resend-verification budget, and the status the
 * middleware returns when its backing store is unreachable while fail-closed.
 *
 * The escalating backoff schedule and the key-derivation rules are unit-tested
 * in internal/ratelimit against Redis directly and are not repeated here.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
)

// resendBudget is the number of resend requests allowed per window in these
// tests. It is small so the budget can be exhausted quickly.
const resendBudget = 3

// TestResendVerificationRateLimited checks that repeated verification-email
// resends for one address are throttled.
//
// Resends cost money and land in a third party's inbox, so an unthrottled
// endpoint is both a billing problem and a way to use the engine to spam an
// address its owner never signed up with.
func TestResendVerificationRateLimited(t *testing.T) {
	resendLimiter := ratelimit.NewLimiter(ratelimit.Options{
		Enabled:            true,
		FailClosed:         false,
		MaxAttempts:        resendBudget,
		Window:             time.Hour,
		IPBudgetMultiplier: 10,
		ViolationReset:     7 * 24 * time.Hour,
	})

	env := newTestEnv(t, nil, resendLimiter)

	const address = "resend_target@example.com"
	if resp := env.signUp(t, address, "SecurePass123!", "Resend Target"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	payload := map[string]string{
		"email":       address,
		"tenant_id":   testTenant,
		"environment": testEnvironment,
	}

	// The budget is spent first. These replies are not asserted on beyond "not
	// throttled": whether a resend succeeds or reports an already-verified
	// account is not what this test is about.
	for attempt := 1; attempt <= resendBudget; attempt++ {
		resp := env.do(t, http.MethodPost, "/v1/client/resend-verification", payload)
		if resp.status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d of %d was throttled before the budget was spent; body %s",
				attempt, resendBudget, resp.body)
		}
	}

	throttled := env.do(t, http.MethodPost, "/v1/client/resend-verification", payload)
	if throttled.status != http.StatusTooManyRequests {
		t.Fatalf("resend past the budget: got status %d, want 429; body %s",
			throttled.status, throttled.body)
	}
}

// TestRateLimiterFailsClosedWithUnreachableStore checks that a fail-closed
// limiter whose store is unreachable refuses requests with 503 rather than
// letting them through.
//
// 503 is the correct status and 429 is not: the caller is not over budget, the
// engine simply cannot tell. Returning 429 would advertise a limit that is not
// being enforced, and returning 200 would leave credential endpoints unguarded
// for exactly as long as the outage lasts.
//
// No Redis is required — a limiter configured with no client is unreachable by
// construction, which is the same condition the middleware sees during an
// outage.
func TestRateLimiterFailsClosedWithUnreachableStore(t *testing.T) {
	limiter := ratelimit.NewLimiter(ratelimit.Options{
		Enabled:            true,
		FailClosed:         true,
		MaxAttempts:        5,
		Window:             15 * time.Minute,
		IPBudgetMultiplier: 10,
		ViolationReset:     7 * 24 * time.Hour,
	})

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(limiter.Middleware())
	app.Post("/v1/client/login", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusUnauthorized)
	})

	req, err := http.NewRequest(http.MethodPost, "/v1/client/login",
		strings.NewReader(`{"email":"user@example.com","password":"guess"}`))
	if err != nil {
		t.Fatalf("building the login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, requestTimeoutMillis)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login while the limiter store is unreachable: got status %d, want 503; "+
			"a fail-closed limiter must not admit unthrottled credential attempts", resp.StatusCode)
	}
}

// TestRateLimiterOpenWhenStoreUnreachableAndFailOpen is the counterpart: with
// fail-closed off, an unreachable store falls back to the per-process in-memory
// window instead of rejecting everything.
//
// This is the development default. It keeps a local clone working without
// Redis, and it is why RATELIMIT_FAIL_CLOSED defaults to on only in production.
func TestRateLimiterOpenWhenStoreUnreachableAndFailOpen(t *testing.T) {
	limiter := ratelimit.NewLimiter(ratelimit.Options{
		Enabled:            true,
		FailClosed:         false,
		MaxAttempts:        5,
		Window:             15 * time.Minute,
		IPBudgetMultiplier: 10,
		ViolationReset:     7 * 24 * time.Hour,
	})

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(limiter.Middleware())
	app.Post("/v1/client/login", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusUnauthorized)
	})

	req, err := http.NewRequest(http.MethodPost, "/v1/client/login",
		strings.NewReader(`{"email":"failopen@example.com","password":"guess"}`))
	if err != nil {
		t.Fatalf("building the login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, requestTimeoutMillis)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with a fail-open limiter and no store: got status %d, want 401 "+
			"(the request should reach the handler)", resp.StatusCode)
	}
}
