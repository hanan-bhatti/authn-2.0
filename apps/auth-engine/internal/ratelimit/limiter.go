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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
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

// Check evaluates whether a request identified by key is allowed.
// Returns (allowed bool, retryAfter time.Duration, err error).
func (l *Limiter) Check(ctx context.Context, key string) (bool, time.Duration, error) {
	if !l.enabled {
		return true, 0, nil
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
		res, err := l.redisClient.Eval(ctx, slidingWindowLua, []string{attemptKey}, nowUnix, l.windowSeconds, l.maxAttempts).Result()
		if err != nil {
			if l.failClosed || l.isProduction {
				return false, 0, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
			}
			// In dev mode without Redis, fallback to in-memory check
			allowed := l.checkInMemory(key, l.maxAttempts, time.Duration(l.windowSeconds)*time.Second)
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
	allowed := l.checkInMemory(key, l.maxAttempts, time.Duration(l.windowSeconds)*time.Second)
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
func BuildKey(tenantID string, ip string, account string, endpoint string) string {
	hasher := sha256.New()
	hasher.Write([]byte(ip + ":" + account))
	hash := hex.EncodeToString(hasher.Sum(nil))[:16]
	return fmt.Sprintf("%s:%s:%s", tenantID, endpoint, hash)
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
		ip := c.IP()
		userAgent := c.Get("User-Agent")
		key := BuildKey(tenantID, ip, userAgent, c.Path())

		allowed, retryAfter, err := l.Check(c.UserContext(), key)
		if err != nil {
			if errors.Is(err, ErrRedisUnavailable) {
				return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
					"error": "rate limit service unavailable",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal rate limiter error",
			})
		}

		if !allowed {
			if retryAfter > 0 {
				c.Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			}
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":               "too many attempts, please try again later",
				"retry_after_seconds": int(retryAfter.Seconds()),
			})
		}

		return c.Next()
	}
}
