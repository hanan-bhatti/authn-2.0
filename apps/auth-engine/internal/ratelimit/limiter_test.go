package ratelimit

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

func TestLimiter_InMemorySlidingWindow(t *testing.T) {
	schedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	limiter := NewLimiter(nil, false, true, true, 5, 60, schedule, 7)
	ctx := context.Background()
	key := "test_ratelimit_key"

	// 5 attempts allowed
	for i := 1; i <= 5; i++ {
		allowed, _, err := limiter.Check(ctx, key)
		if err != nil {
			t.Fatalf("unexpected error on attempt %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("expected attempt %d to be allowed", i)
		}
	}

	// 6th attempt blocked (429)
	allowed, _, err := limiter.Check(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error on 6th attempt: %v", err)
	}
	if allowed {
		t.Fatalf("expected 6th attempt to be blocked")
	}
}

func TestLimiter_FailClosedProduction(t *testing.T) {
	schedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	// Production mode without Redis connection must fail-closed
	limiter := NewLimiter(nil, true, true, true, 5, 60, schedule, 7)
	ctx := context.Background()

	allowed, _, err := limiter.Check(ctx, "test_prod_key")
	if allowed {
		t.Fatalf("expected fail-closed production check to deny access when Redis is nil")
	}
	if err == nil {
		t.Fatalf("expected ErrRedisUnavailable error in production fail-closed mode")
	}
}

func TestLimiter_RedisExponentialBackoff(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("skipping Redis integration test: Redis not reachable on localhost:6379")
	}

	schedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	limiter := NewLimiter(client, false, true, true, 2, 60, schedule, 7)

	testKey := "test_backoff_key_unit"
	attemptKey := "ratelimit:attempt:" + testKey
	blockKey := "ratelimit:block:" + testKey
	violKey := "ratelimit:viol_cnt:" + testKey

	// Cleanup key before test
	client.Del(ctx, attemptKey, blockKey, violKey)
	t.Cleanup(func() {
		client.Del(ctx, attemptKey, blockKey, violKey)
	})

	// 2 attempts allowed
	for i := 1; i <= 2; i++ {
		allowed, _, err := limiter.Check(ctx, testKey)
		if err != nil || !allowed {
			t.Fatalf("attempt %d should be allowed, got allowed=%v, err=%v", i, allowed, err)
		}
	}

	// Violation 1 (3rd attempt): should trigger 15m block
	allowed, retryAfter, err := limiter.Check(ctx, testKey)
	if allowed || err != nil {
		t.Fatalf("3rd attempt should be blocked, got allowed=%v, err=%v", allowed, err)
	}
	if retryAfter != 15*time.Minute {
		t.Fatalf("expected 1st violation retryAfter to be 15m, got %v", retryAfter)
	}

	// Verify Redis block key TTL is ~15m (900s)
	ttl, _ := client.TTL(ctx, blockKey).Result()
	if ttl < 890*time.Second || ttl > 900*time.Second {
		t.Fatalf("expected block TTL ~900s, got %v", ttl)
	}

	// Verify violation counter key TTL is ~7 days (604800s)
	violTTL, _ := client.TTL(ctx, violKey).Result()
	if violTTL < 604700*time.Second || violTTL > 604800*time.Second {
		t.Fatalf("expected violation count TTL ~604800s, got %v", violTTL)
	}

	// Simulate block expiry via DEL
	client.Del(ctx, blockKey)

	// Violation 2: should trigger 1h block
	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	if allowed || retryAfter != 1*time.Hour {
		t.Fatalf("expected 2nd violation 1h block, got allowed=%v, retryAfter=%v", allowed, retryAfter)
	}

	// Simulate block expiry via DEL
	client.Del(ctx, blockKey)

	// Violation 3: should trigger 6h block
	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	if allowed || retryAfter != 6*time.Hour {
		t.Fatalf("expected 3rd violation 6h block, got allowed=%v, retryAfter=%v", allowed, retryAfter)
	}

	// Simulate block expiry via DEL
	client.Del(ctx, blockKey)

	// Violation 4: should trigger 24h block (capped)
	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	if allowed || retryAfter != 24*time.Hour {
		t.Fatalf("expected 4th violation 24h block cap, got allowed=%v, retryAfter=%v", allowed, retryAfter)
	}
}

func TestBuildKey(t *testing.T) {
	key1 := BuildKey("tnt_demo", "127.0.0.1", "user@example.com", "/v1/client/login")
	key2 := BuildKey("tnt_demo", "127.0.0.1", "user@example.com", "/v1/client/login")
	key3 := BuildKey("tnt_demo", "192.168.1.1", "user@example.com", "/v1/client/login")

	if key1 != key2 {
		t.Fatalf("expected identical keys for identical inputs")
	}
	if key1 == key3 {
		t.Fatalf("expected different keys for different IP addresses")
	}
}

// TestBuildKey_DimensionsCannotCollide guards the two-bucket scheme in
// Middleware: an IP-only key and an account-only key must never hash equal,
// or one dimension would silently consume the other's budget.
func TestBuildKey_DimensionsCannotCollide(t *testing.T) {
	ipOnly := BuildKey("tnt_demo", "127.0.0.1", "", "/v1/client/login")
	accountOnly := BuildKey("tnt_demo", "", "127.0.0.1", "/v1/client/login")

	if ipOnly == accountOnly {
		t.Fatalf("IP-dimension and account-dimension keys collided: %s", ipOnly)
	}

	// Account matching is case/whitespace-insensitive so User@Example.com and
	// user@example.com cannot be used as two separate buckets.
	if BuildKey("t", "", "User@Example.com ", "/p") != BuildKey("t", "", "user@example.com", "/p") {
		t.Fatalf("expected account normalization to collapse case and whitespace")
	}
}

// TestExtractAccountIdentifier covers the input that decides the per-account
// bucket. Before this existed, Middleware keyed on the User-Agent header, so an
// attacker who hit the 5-attempt block got an unlimited supply of fresh buckets
// by changing one client-controlled header.
func TestExtractAccountIdentifier(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{name: "login email", body: `{"email":"user@example.com","password":"x"}`, want: "user@example.com"},
		{name: "email normalized", body: `{"email":"  User@Example.COM  "}`, want: "user@example.com"},
		{name: "username fallback", body: `{"username":"alex"}`, want: "alex"},
		{name: "identifier fallback", body: `{"identifier":"alex@corp.io"}`, want: "alex@corp.io"},
		{name: "email wins over username", body: `{"username":"alex","email":"a@b.co"}`, want: "a@b.co"},
		{name: "empty body", body: ``, want: ""},
		{name: "non-json body", body: `not json at all`, want: ""},
		{name: "token-only endpoint", body: `{"refresh_token":"abc"}`, want: ""},
		{name: "non-string email is ignored", body: `{"email":12345}`, want: ""},
		{name: "blank email is ignored", body: `{"email":"   "}`, want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			var got string
			app.Post("/p", func(c *fiber.Ctx) error {
				got = extractAccountIdentifier(c)
				return c.SendStatus(fiber.StatusOK)
			})

			req := httptest.NewRequest("POST", "/p", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			if _, err := app.Test(req); err != nil {
				t.Fatalf("request failed: %v", err)
			}
			if got != tc.want {
				t.Errorf("extractAccountIdentifier(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

// TestMiddleware_UserAgentRotationCannotBypass is the regression test for the
// live-verified bypass: exhaust the limit, then rotate the User-Agent and
// confirm the request is still blocked.
func TestMiddleware_UserAgentRotationCannotBypass(t *testing.T) {
	limiter := NewLimiter(nil, false, false, true, 5, 900, nil, 7)

	app := fiber.New()
	app.Use(limiter.Middleware())
	app.Post("/v1/client/login", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusUnauthorized) // wrong password
	})

	body := `{"email":"victim@example.com","password":"guess"}`
	post := func(userAgent string) int {
		req := httptest.NewRequest("POST", "/v1/client/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		return resp.StatusCode
	}

	// Burn the 5-attempt budget on one User-Agent.
	for i := 1; i <= 5; i++ {
		if got := post("AttackerAgent/1.0"); got != fiber.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 (allowed through), got %d", i, got)
		}
	}
	if got := post("AttackerAgent/1.0"); got != fiber.StatusTooManyRequests {
		t.Fatalf("expected 429 once the budget is spent, got %d", got)
	}

	// Rotate the User-Agent — must stay blocked.
	for _, ua := range []string{"AttackerAgent/2.0", "AttackerAgent/3.0", "", "curl/8.4.0"} {
		if got := post(ua); got != fiber.StatusTooManyRequests {
			t.Fatalf("User-Agent %q bypassed the limiter: got %d, want 429", ua, got)
		}
	}
}

// TestMiddleware_AccountBucketSurvivesIPRotation covers the other new
// dimension: a single target account cannot be hammered from rotating IPs.
func TestMiddleware_AccountBucketSurvivesIPRotation(t *testing.T) {
	limiter := NewLimiter(nil, false, false, true, 5, 900, nil, 7)

	// ProxyHeader makes c.IP() read X-Forwarded-For; without it Fiber returns the
	// same remote address for every app.Test request and the per-IP bucket alone
	// would explain the block, hiding whether the account bucket works at all.
	app := fiber.New(fiber.Config{ProxyHeader: fiber.HeaderXForwardedFor})
	app.Use(limiter.Middleware())
	app.Post("/v1/client/login", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusUnauthorized)
	})

	post := func(ip, email string) int {
		req := httptest.NewRequest("POST", "/v1/client/login",
			strings.NewReader(`{"email":"`+email+`","password":"guess"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		req.RemoteAddr = ip + ":54321"
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		return resp.StatusCode
	}

	for i := 1; i <= 5; i++ {
		if got := post("10.0.0."+string(rune('0'+i)), "victim@example.com"); got != fiber.StatusUnauthorized {
			t.Fatalf("attempt %d from a fresh IP should pass the IP bucket, got %d", i, got)
		}
	}
	if got := post("10.0.0.99", "victim@example.com"); got != fiber.StatusTooManyRequests {
		t.Fatalf("expected the per-account bucket to block a 6th IP, got %d", got)
	}

	// A different account from a fresh IP is unaffected.
	if got := post("10.0.0.99", "bystander@example.com"); got != fiber.StatusUnauthorized {
		t.Fatalf("unrelated account must not be collateral-blocked, got %d", got)
	}
}

// TestMiddleware_SharedNATNotCollateralBlocked pins the reason the per-IP
// dimension carries a wider budget than the per-account one. Removing the
// User-Agent from the key made the IP bucket effective for the first time; at
// the same 5-attempt budget, one user's typos would lock out every colleague
// behind the same NAT egress.
func TestMiddleware_SharedNATNotCollateralBlocked(t *testing.T) {
	limiter := NewLimiter(nil, false, false, true, 5, 900, nil, 7)

	app := fiber.New(fiber.Config{ProxyHeader: fiber.HeaderXForwardedFor})
	app.Use(limiter.Middleware())
	app.Post("/v1/client/login", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusUnauthorized)
	})

	post := func(email string) int {
		req := httptest.NewRequest("POST", "/v1/client/login",
			strings.NewReader(`{"email":"`+email+`","password":"guess"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "203.0.113.7") // one office egress
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		return resp.StatusCode
	}

	// One colleague exhausts their own account budget.
	for i := 1; i <= 5; i++ {
		if got := post("typo.user@example.com"); got != fiber.StatusUnauthorized {
			t.Fatalf("attempt %d should reach the handler, got %d", i, got)
		}
	}
	if got := post("typo.user@example.com"); got != fiber.StatusTooManyRequests {
		t.Fatalf("expected that account to be blocked, got %d", got)
	}

	// Colleagues on the same IP are still served.
	for _, email := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
		if got := post(email); got != fiber.StatusUnauthorized {
			t.Fatalf("%s behind the same NAT was collateral-blocked: got %d", email, got)
		}
	}
}

// TestMiddleware_TokenOnlyEndpointKeepsStrictIPLimit ensures widening the IP
// budget did not loosen endpoints that carry no account identifier — there is no
// account bucket to fall back on there, so the IP dimension must stay strict.
func TestMiddleware_TokenOnlyEndpointKeepsStrictIPLimit(t *testing.T) {
	limiter := NewLimiter(nil, false, false, true, 5, 900, nil, 7)

	app := fiber.New()
	app.Use(limiter.Middleware())
	app.Post("/v1/client/auth/refresh", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusUnauthorized)
	})

	post := func() int {
		req := httptest.NewRequest("POST", "/v1/client/auth/refresh",
			strings.NewReader(`{"refresh_token":"forged"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		return resp.StatusCode
	}

	for i := 1; i <= 5; i++ {
		if got := post(); got != fiber.StatusUnauthorized {
			t.Fatalf("attempt %d should reach the handler, got %d", i, got)
		}
	}
	if got := post(); got != fiber.StatusTooManyRequests {
		t.Fatalf("token-only endpoint must stay at the configured limit, got %d", got)
	}
}
