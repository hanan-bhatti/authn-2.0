/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/ratelimit/limiter.go
 * Tier: Internal Feature Package / Rate Limiter
 *
 * Multi-dimensional sliding-window rate limiter for credential-checking
 * endpoints.
 *
 * Every request is measured on two independent dimensions — the account it is
 * acting against and the address it came from — and must pass both. The window
 * is a Redis sorted set trimmed and tested by a single Lua script, so counting
 * is atomic and shared across instances. Repeat offenders are escalated onto a
 * backoff schedule, and an unreachable Redis either fails closed or falls back to
 * a per-process counter, according to configuration.
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
	// ErrRateLimitExceeded reports that a caller has spent its budget for the
	// current window.
	ErrRateLimitExceeded = errors.New("rate limit exceeded: too many requests")
	// ErrRedisUnavailable reports that the limiter could not reach its backing
	// store and, being configured fail-closed, refused the request rather than
	// letting it through uncounted.
	ErrRedisUnavailable = errors.New("rate limit service unavailable: fail-closed security policy enforced")
)

// slidingWindowLua trims the window and tests the budget in one atomic step.
//
// KEYS[1] is the attempt set; ARGV is (now, window, limit). Entries older than
// now-window are dropped, the remainder counted, and a new member added only if
// the count is below the limit. Returns 1 when the request is admitted, 0 when
// it is not. Running this as a script is what keeps read-then-write from racing
// between instances, which would let concurrent attempts each see a stale count.
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

// maxIdentifierBodyBytes caps how much request body extractAccountIdentifier
// will parse. A body larger than this is not a login payload, and parsing it
// would let a caller spend the server's CPU on JSON it does not intend to use.
const maxIdentifierBodyBytes = 64 * 1024

// inMemoryCounter is one key's window in the per-process fallback store.
type inMemoryCounter struct {
	// timestamps holds the admitted attempts still inside the window.
	timestamps []time.Time
}

// Limiter enforces the configured budgets against Redis, or against a
// per-process fallback when Redis is absent. It is safe for concurrent use.
type Limiter struct {
	// redisClient backs the shared window. Nil selects the in-memory fallback.
	redisClient *redis.Client
	// failClosed refuses requests the limiter cannot count.
	failClosed bool
	// enabled turns limiting on; when false every check is admitted.
	enabled bool
	// maxAttempts is the per-window budget for one account.
	maxAttempts int
	// window is the period over which attempts are counted.
	window time.Duration
	// ipBudgetMultiplier scales the per-IP budget above the per-account one.
	ipBudgetMultiplier int
	// backoffSchedule is the escalating lockout indexed by violation count,
	// longest last; the final entry is the cap.
	backoffSchedule []time.Duration
	// violationReset is the idle time after which an offender's escalation level
	// decays back to zero.
	violationReset time.Duration
	// mu guards memStore.
	mu sync.Mutex
	// memStore is the per-process fallback window, keyed as Redis would be.
	memStore map[string]*inMemoryCounter
}

// Options configures a Limiter.
//
// Every value is supplied by the caller from validated configuration; the
// constructor substitutes no defaults of its own, so there is exactly one place
// in the codebase that decides what a sensible limit is.
type Options struct {
	// Redis backs the shared sliding window. When nil, the limiter falls back
	// to a per-process in-memory counter, which cannot coordinate across
	// instances and is only appropriate for single-instance or test use.
	Redis *redis.Client
	// Enabled turns limiting on. Disable only in tests.
	Enabled bool
	// FailClosed rejects requests when Redis is unreachable rather than letting
	// them through unchecked. Safer, at the cost of availability during an
	// outage of the limiter's own dependency.
	FailClosed bool
	// MaxAttempts is the allowance per window for one account.
	MaxAttempts int
	// Window is the period over which attempts are counted.
	Window time.Duration
	// IPBudgetMultiplier widens the per-IP allowance relative to the
	// per-account one, so a shared office or carrier address is not locked out
	// by a single user's mistakes.
	IPBudgetMultiplier int
	// BackoffSchedule is the escalating lockout for repeat offenders.
	BackoffSchedule []time.Duration
	// ViolationReset is how long a clean record must last before an offender's
	// escalation level returns to zero.
	ViolationReset time.Duration
}

// NewLimiter constructs a rate limiter from validated options.
func NewLimiter(opts Options) *Limiter {
	return &Limiter{
		redisClient:        opts.Redis,
		failClosed:         opts.FailClosed,
		enabled:            opts.Enabled,
		maxAttempts:        opts.MaxAttempts,
		window:             opts.Window,
		ipBudgetMultiplier: opts.IPBudgetMultiplier,
		backoffSchedule:    opts.BackoffSchedule,
		violationReset:     opts.ViolationReset,
		memStore:           make(map[string]*inMemoryCounter),
	}
}

// Check evaluates key against the limiter's configured per-account budget.
//
// It returns whether the request is admitted, how long the caller must wait when
// it is not (zero when unknown, as in the in-memory fallback), and an error only
// when the limiter could not reach its store while configured fail-closed —
// ErrRedisUnavailable, which callers translate to 503 rather than 429.
func (l *Limiter) Check(ctx context.Context, key string) (bool, time.Duration, error) {
	return l.CheckWithLimit(ctx, key, l.maxAttempts)
}

// CheckWithLimit is Check with an explicit budget, so independent dimensions of
// one request can carry different allowances — see Middleware, where the
// per-account bucket is strict and the per-IP bucket is wider. A maxAttempts of
// zero or less falls back to the configured per-account budget.
//
// Exceeding the budget increments the key's violation counter and installs a
// block whose lifetime is the backoff step for that count, so the returned
// retryAfter lengthens with each repeat offence until the schedule's last entry
// caps it.
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

		// An active block short-circuits the window entirely: its remaining TTL is
		// the retry-after the caller is owed.
		blockTTL, err := l.redisClient.TTL(ctx, blockKey).Result()
		if err == nil && blockTTL > 0 {
			return false, blockTTL, nil
		}

		nowUnix := time.Now().Unix()
		res, err := l.redisClient.Eval(ctx, slidingWindowLua, []string{attemptKey}, nowUnix, int(l.window.Seconds()), maxAttempts).Result()
		if err != nil {
			if l.failClosed {
				return false, 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
			}
			allowed := l.checkInMemory(key, maxAttempts, l.window)
			return allowed, 0, nil
		}

		allowedVal, ok := res.(int64)
		if ok && allowedVal == 1 {
			return true, 0, nil
		}

		// Over budget: escalate. The counter's TTL is refreshed on every offence,
		// so the escalation level decays only after a full quiet violationReset.
		violCount, err := l.redisClient.Incr(ctx, violKey).Result()
		if err != nil {
			violCount = 1
		}
		_ = l.redisClient.Expire(ctx, violKey, l.violationReset)

		stepIdx := int(violCount) - 1
		if stepIdx < 0 {
			stepIdx = 0
		}
		if stepIdx >= len(l.backoffSchedule) {
			stepIdx = len(l.backoffSchedule) - 1
		}
		backoffDuration := l.backoffSchedule[stepIdx]

		_ = l.redisClient.Set(ctx, blockKey, "blocked", backoffDuration).Err()

		return false, backoffDuration, nil
	}

	// No Redis configured. Fail-closed deployments refuse rather than fall back
	// to a counter that cannot see the other instances.
	if l.failClosed {
		return false, 0, ErrRedisUnavailable
	}
	allowed := l.checkInMemory(key, maxAttempts, l.window)
	return allowed, 0, nil
}

// checkInMemory applies the sliding window to the per-process store and reports
// whether the attempt is admitted, recording it when it is. It carries no
// escalation and no cross-instance visibility, so it is a development and test
// fallback rather than a substitute for Redis.
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

// BuildKey constructs a bucket key of the form "{tenant}:{endpoint}:{hash}",
// where the hash covers ip + ":" + account.
//
// Because the two values sit on opposite sides of the separator, an IP-only key
// (account == "") can never collide with an account-only key (ip == ""), which
// is what lets one function derive both of Middleware's independent dimensions.
//
// account is the target identity of the request — the email being logged into —
// and never a client-controlled header. Anything a caller can vary at will makes
// the bucket a caller-chosen namespace, which is to say no limit at all.
func BuildKey(tenantID string, ip string, account string, endpoint string) string {
	hasher := sha256.New()
	hasher.Write([]byte(ip + ":" + strings.ToLower(strings.TrimSpace(account))))
	hash := hex.EncodeToString(hasher.Sum(nil))[:16]
	return fmt.Sprintf("%s:%s:%s", tenantID, endpoint, hash)
}

// accountIdentifierFields are the JSON body fields, in precedence order, that
// name the account a request is acting against.
var accountIdentifierFields = []string{"email", "username", "identifier", "phone_number"}

// challengeIdentifierFields are the opaque per-attempt credentials that stand in
// for an account when the body carries no human identifier.
//
// Second-factor verification (POST /2fa/totp/verify, /auth/2fa/verify,
// /2fa/webauthn/login/*) posts {"code", "mfa_token"} and nothing else — no
// email, no username. Without this fallback such a request has no account
// dimension and is bucketed by IP alone, and a six-digit TOTP is a 10^6
// keyspace: an attacker who already holds the password (they must, to possess an
// mfa_token) rotates source addresses and brute-forces the second factor with no
// effective ceiling.
//
// Keying on the challenge credential binds the budget to the login attempt
// itself, which no amount of IP rotation escapes. Minting a fresh mfa_token
// costs another /login, and that path is bucketed per-account by email.
var challengeIdentifierFields = []string{"mfa_token", "session_id"}

// extractAccountIdentifier resolves the target account from the request body so
// the limiter can enforce a per-account bucket an attacker cannot escape by
// rotating IPs. It returns a lowercased identifier, a "chal_"-prefixed digest of
// the challenge credential when the body carries only that, or "" when neither
// is present — in which case only the per-IP bucket applies.
//
// The challenge credential is hashed rather than used verbatim because the
// resulting key is stored in Redis and may be logged, while an mfa_token is a
// live credential until it is redeemed.
//
// Reading c.Body() here is safe: Fiber buffers the body, so a later BodyParser
// in the handler still sees it.
func extractAccountIdentifier(c *fiber.Ctx) string {
	body := c.Body()
	if len(body) == 0 || len(body) > maxIdentifierBodyBytes {
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

// Middleware returns a Fiber handler that measures each request on every
// applicable dimension and answers 429 with a Retry-After header on the first
// one that is over budget, or 503 when the limiter is fail-closed and cannot
// reach its store.
//
// Two dimensions apply, and both must pass:
//
//  1. per-account — keyed on the target identity at the configured budget. This
//     is the brute-force defence, and it holds however the attacker moves,
//     because login has no separate account-lockout engine behind it.
//  2. per-IP — keyed on the source address, catching one host spraying many
//     accounts.
//
// The User-Agent is not part of either key, and no client-controlled header ever
// can be. A header in the key gives the attacker the bucket: changing one string
// mints a fresh budget, and the limit becomes unlimited guesses from a single
// address.
//
// The per-IP budget is widened by ipBudgetMultiplier only when an account bucket
// is also in force on the same request. A shared egress — corporate NAT, campus,
// mobile carrier — legitimately produces many logins from one address, and the
// strict per-account limit is what actually stops guessing; holding the IP
// dimension at the same number would lock out an entire office over one user's
// typos. Requests with no identifier in the body (token-only refresh, verify)
// have no account bucket to lean on, so their IP dimension stays at the
// configured limit.
func (l *Limiter) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !l.enabled {
			return c.Next()
		}

		tenantID := c.Query("tenant_id", "tnt_default")
		if tID, ok := c.Locals("tenant_id").(string); ok && tID != "" {
			tenantID = tID
		}

		ip := c.IP()
		account := extractAccountIdentifier(c)

		// dimension pairs a bucket key with the budget it is measured against.
		type dimension struct {
			key   string
			limit int
		}
		dims := make([]dimension, 0, 2)
		if account != "" {
			dims = append(dims,
				dimension{key: BuildKey(tenantID, "", account, c.Path()), limit: l.maxAttempts},
				dimension{key: BuildKey(tenantID, ip, "", c.Path()), limit: l.maxAttempts * l.ipBudgetMultiplier},
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
				// what the SDK reads (packages/sdk-js/src/http.ts parses the header,
				// not the body). The body stays the canonical {error, code}
				// envelope.
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
