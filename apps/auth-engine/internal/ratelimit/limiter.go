/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/ratelimit/limiter.go
 * Tier: Internal Feature Package / Rate Limiter
 *
 * Description: Multi-dimensional sliding-window rate limiter with Redis ZSET Lua script,
 *              exponential backoff on repeat violations, violation counter tracking,
 *              and fail-closed outage protection for security-critical auth endpoints.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/redis/go-redis/v9"
)

var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded: too many requests")
	ErrRedisUnavailable  = errors.New("rate limit service unavailable: fail-closed security policy enforced")
)

const slidingWindowLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local clearBefore = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', clearBefore)
local currentRequests = redis.call('ZCARD', key)

if currentRequests < limit then
    redis.call('ZADD', key, now, tostring(now) .. '-' .. tostring(math.random(100000, 999999)))
    redis.call('EXPIRE', key, window)
    return 1
else
    return 0
end
`

type inMemoryCounter struct {
	timestamps []time.Time
}

// Limiter manages rate limits across Redis and in-memory fallbacks.
type Limiter struct {
	redisClient        *redis.Client
	isProduction       bool
	failClosed         bool
	enabled            bool
	maxAttempts        int
	windowSeconds      int
	backoffSchedule    []time.Duration
	violationResetDays int
	mu                 sync.Mutex
	memStore           map[string]*inMemoryCounter
}

// NewLimiter constructs a new Rate Limiter instance with full configurability.
func NewLimiter(redisClient *redis.Client, isProduction bool, failClosed bool, enabled bool, maxAttempts int, windowSeconds int, schedule []time.Duration, resetDays int) *Limiter {
	if len(schedule) == 0 {
		schedule = []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if windowSeconds <= 0 {
		windowSeconds = 900
	}
	if resetDays <= 0 {
		resetDays = 7
	}

	return &Limiter{
		redisClient:        redisClient,
		isProduction:       isProduction,
		failClosed:         failClosed,
		enabled:            enabled,
		maxAttempts:        maxAttempts,
		windowSeconds:      windowSeconds,
		backoffSchedule:    schedule,
		violationResetDays: resetDays,
		memStore:           make(map[string]*inMemoryCounter),
	}
}

// Check evaluates whether a request identified by key is allowed against the
// limiter's configured maxAttempts.
// Returns (allowed bool, retryAfter time.Duration, err error).
func (l *Limiter) Check(ctx context.Context, key string) (bool, time.Duration, error) {
	return l.CheckWithLimit(ctx, key, l.maxAttempts)
}

// CheckWithLimit is Check with an explicit budget, so independent dimensions of
// the same request can carry different allowances — see Middleware, where the
// per-account bucket is strict and the per-IP bucket is wider to avoid locking
// out everyone behind a shared NAT egress.
func (l *Limiter) CheckWithLimit(ctx context.Context, key string, maxAttempts int) (bool, time.Duration, error) {
	if !l.enabled {
		return true, 0, nil
	}
	if maxAttempts <= 0 {
		maxAttempts = l.maxAttempts
	}

	if l.redisClient != nil {
		attemptKey := fmt.Sprintf("ratelimit:attempt:%s", key)
		blockKey := fmt.Sprintf("ratelimit:block:%s", key)
		violKey := fmt.Sprintf("ratelimit:viol_cnt:%s", key)

		// 1. Check if an active block key exists in Redis
		blockTTL, err := l.redisClient.TTL(ctx, blockKey).Result()
		if err == nil && blockTTL > 0 {
			return false, blockTTL, nil
		}

		// 2. Evaluate sliding window Lua script
		nowUnix := time.Now().Unix()
		res, err := l.redisClient.Eval(ctx, slidingWindowLua, []string{attemptKey}, nowUnix, l.windowSeconds, maxAttempts).Result()
		if err != nil {
			if l.failClosed || l.isProduction {
				return false, 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
			}
			// In dev mode without Redis, fallback to in-memory check
			allowed := l.checkInMemory(key, maxAttempts, time.Duration(l.windowSeconds)*time.Second)
			return allowed, 0, nil
		}

		allowedVal, ok := res.(int64)
		if ok && allowedVal == 1 {
			return true, 0, nil
		}

		// 3. Rate limit exceeded — escalate violation counter in Redis
		violCount, err := l.redisClient.Incr(ctx, violKey).Result()
		if err != nil {
			violCount = 1
		}

		// Refresh violation counter TTL to resetDays (default 7 days)
		resetTTL := time.Duration(l.violationResetDays) * 24 * time.Hour
		_ = l.redisClient.Expire(ctx, violKey, resetTTL)

		// Determine backoff duration based on violation count (1st: 15m, 2nd: 1h, 3rd: 6h, 4th+: 24h cap)
		stepIdx := int(violCount) - 1
		if stepIdx < 0 {
			stepIdx = 0
		}
		if stepIdx >= len(l.backoffSchedule) {
			stepIdx = len(l.backoffSchedule) - 1
		}
		backoffDuration := l.backoffSchedule[stepIdx]

		// Set active block key with backoff TTL
		_ = l.redisClient.Set(ctx, blockKey, "blocked", backoffDuration).Err()

		return false, backoffDuration, nil
	}

	// Dev mode in-memory fallback (no escalation, simple sliding window)
	if l.failClosed && l.isProduction {
		return false, 0, ErrRedisUnavailable
	}
	allowed := l.checkInMemory(key, maxAttempts, time.Duration(l.windowSeconds)*time.Second)
	return allowed, 0, nil
}

func (l *Limiter) checkInMemory(key string, maxAttempts int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	entry, exists := l.memStore[key]
	if !exists {
		l.memStore[key] = &inMemoryCounter{timestamps: []time.Time{now}}
		return true
	}

	// Filter timestamps within sliding window
	valid := make([]time.Time, 0, len(entry.timestamps))
	for _, t := range entry.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= maxAttempts {
		entry.timestamps = valid
		return false
	}

	entry.timestamps = append(valid, now)
	return true
}

// BuildKey constructs a multi-dimensional rate limit key (ratelimit:{tenant}:{endpoint}:{hash}).
//
// The hash covers ip + ":" + account. Because the two values sit on opposite
// sides of the separator, an IP-only key (account == "") can never collide with
// an account-only key (ip == ""), so the caller can derive two independent
// buckets from this one function.
//
// NOTE: `account` means the *target identity* of the request (the email being
// logged into), NOT the User-Agent. Passing a client-controlled header here
// makes the limiter trivially bypassable — see extractAccountIdentifier.
func BuildKey(tenantID string, ip string, account string, endpoint string) string {
	hasher := sha256.New()
	hasher.Write([]byte(ip + ":" + strings.ToLower(strings.TrimSpace(account))))
	hash := hex.EncodeToString(hasher.Sum(nil))[:16]
	return fmt.Sprintf("%s:%s:%s", tenantID, endpoint, hash)
}

// accountIdentifierFields are the JSON body fields, in precedence order, that
// name the account a request is acting against.
var accountIdentifierFields = []string{"email", "username", "identifier", "phone_number"}

// challengeIdentifierFields name opaque per-attempt credentials that stand in
// for an account when the body carries no human identifier.
//
// Second-factor verification (POST /2fa/totp/verify, /auth/2fa/verify,
// /2fa/webauthn/login/*) posts {"code", "mfa_token"} — no email, no username.
// extractAccountIdentifier therefore returned "" and the request fell through
// to the per-IP dimension ALONE. A six-digit TOTP is a 10^6 keyspace, and an
// attacker who already holds the password (they must, to have obtained an
// mfa_token) could rotate source IPs and brute-force the second factor with no
// effective ceiling.
//
// Keying on the challenge token binds the budget to the login attempt itself,
// which no amount of IP rotation escapes. Minting a fresh mfa_token requires
// another /login, and that path is bucketed per-account by email.
var challengeIdentifierFields = []string{"mfa_token", "session_id"}

// ipBudgetMultiplier widens the per-IP allowance when a per-account bucket is
// also enforcing the strict limit on the same request. It exists so that a
// shared egress IP (corporate NAT, campus, mobile carrier) is not locked out by
// the login attempts of unrelated users.
const ipBudgetMultiplier = 10

// extractAccountIdentifier resolves the target account from the request body so
// the limiter can enforce a per-account bucket that a single attacker cannot
// escape by rotating IPs. Returns "" when no identifier is present (e.g. a
// token-only endpoint), in which case only the per-IP bucket applies.
//
// Reading c.Body() here is safe: Fiber buffers the body, so a later BodyParser
// in the handler still sees it.
func extractAccountIdentifier(c *fiber.Ctx) string {
	body := c.Body()
	if len(body) == 0 || len(body) > 64*1024 {
		return ""
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}

	for _, field := range accountIdentifierFields {
		if v, ok := parsed[field].(string); ok {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				return v
			}
		}
	}

	// No human identifier. Fall back to the challenge credential so that
	// second-factor verification still gets a bucket an attacker cannot shed by
	// changing IP. The token is hashed: the key is stored in Redis and may be
	// logged, and an mfa_token is a live credential until it is redeemed.
	for _, field := range challengeIdentifierFields {
		if v, ok := parsed[field].(string); ok {
			if v = strings.TrimSpace(v); v != "" {
				sum := sha256.Sum256([]byte(v))
				return "chal_" + hex.EncodeToString(sum[:8])
			}
		}
	}
	return ""
}

// Middleware returns a Fiber middleware enforcing rate limits with exponential backoff.
func (l *Limiter) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !l.enabled {
			return c.Next()
		}

		tenantID := c.Query("tenant_id", "tnt_default")
		if tID, ok := c.Locals("tenant_id").(string); ok && tID != "" {
			tenantID = tID
		}
		// Two independent dimensions, both of which must pass:
		//
		//   1. per-account — the target identity, at the configured budget. This
		//      is the brute-force defense: it holds even if the attacker rotates
		//      IPs, and login has no separate account-lockout engine behind it.
		//   2. per-IP — one host spraying many accounts, at a wider budget.
		//
		// The User-Agent is deliberately NOT part of either key. It used to be
		// passed into BuildKey's `account` slot, which meant an attacker locked
		// out at 5 attempts got a fresh bucket by changing one request header —
		// unlimited password guesses from a single IP.
		//
		// The IP budget is widened only when an account bucket is also in force.
		// A shared NAT egress can legitimately produce many logins from one
		// address, and the strict per-account limit is what actually stops
		// guessing; holding the IP dimension at the same 5 would lock out an
		// entire office for one user's typos. Endpoints with no identifier in the
		// body (token-only refresh, verify, etc.) get no account bucket, so their
		// IP dimension stays at the configured limit.
		ip := c.IP()
		account := extractAccountIdentifier(c)

		type dimension struct {
			key   string
			limit int
		}
		dims := make([]dimension, 0, 2)
		if account != "" {
			dims = append(dims,
				dimension{key: BuildKey(tenantID, "", account, c.Path()), limit: l.maxAttempts},
				dimension{key: BuildKey(tenantID, ip, "", c.Path()), limit: l.maxAttempts * ipBudgetMultiplier},
			)
		} else {
			dims = append(dims, dimension{key: BuildKey(tenantID, ip, "", c.Path()), limit: l.maxAttempts})
		}

		for _, d := range dims {
			allowed, retryAfter, err := l.CheckWithLimit(c.UserContext(), d.key, d.limit)
			if err != nil {
				if errors.Is(err, ErrRedisUnavailable) {
					return httperr.Send(c, fiber.StatusServiceUnavailable,
						httperr.CodeServiceUnavailable, "rate limit service unavailable")
				}
				return httperr.SendInternal(c, "ratelimit.check", err)
			}

			if !allowed {
				// Retry-After is the HTTP-standard carrier for this value and is
				// what the SDK reads (packages/sdk-js/src/http.ts parses the
				// header, not the body). The body stays the canonical flat
				// {error, code} envelope — the former `retry_after_seconds` body
				// field was the only place in the engine that extended it.
				if retryAfter > 0 {
					c.Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
				}
				return httperr.TooManyRequests(c, httperr.CodeRateLimited,
					"too many attempts, please try again later")
			}
		}

		return c.Next()
	}
}
