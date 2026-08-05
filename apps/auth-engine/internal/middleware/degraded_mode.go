/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/degraded_mode.go
 * Tier: Internal Middleware Layer
 *
 * Description: Middleware and background health tracker that monitors live Redis connectivity
 *              and injects the X-Authn-Degraded-Mode response header to inform client SDKs
 *              to fall back to direct DB queries without breaking user sessions.
 *
 * Architecture Note:
 *   - Uses a background 1-second ticker with atomic flag checks to ensure ZERO RTT latency
 *     overhead per HTTP request while accurately reflecting Redis state within 1 second.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

// DegradedModeTracker monitors live Redis connectivity in the background without per-request latency overhead.
type DegradedModeTracker struct {
	redisClient *redis.Client
	isDegraded  int32 // 1 if degraded (Redis down/unreachable), 0 if healthy
	stopChan    chan struct{}
}

// NewDegradedModeTracker initializes a health tracker that pings Redis periodically.
func NewDegradedModeTracker(redisClient *redis.Client, checkInterval time.Duration) *DegradedModeTracker {
	t := &DegradedModeTracker{
		redisClient: redisClient,
		stopChan:    make(chan struct{}),
	}

	if redisClient == nil {
		atomic.StoreInt32(&t.isDegraded, 1)
		return t
	}

	// Perform immediate initial check
	t.checkHealth()

	// Start periodic background ticker
	if checkInterval <= 0 {
		checkInterval = 1 * time.Second
	}
	go t.startTicker(checkInterval)

	return t
}

func (t *DegradedModeTracker) checkHealth() {
	if t.redisClient == nil {
		atomic.StoreInt32(&t.isDegraded, 1)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := t.redisClient.Ping(ctx).Err(); err != nil {
		atomic.StoreInt32(&t.isDegraded, 1)
	} else {
		atomic.StoreInt32(&t.isDegraded, 0)
	}
}

func (t *DegradedModeTracker) startTicker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.checkHealth()
		case <-t.stopChan:
			return
		}
	}
}

// Stop halts the background health ticker.
func (t *DegradedModeTracker) Stop() {
	close(t.stopChan)
}

// IsDegraded returns true if Redis is currently unreachable or disconnected.
func (t *DegradedModeTracker) IsDegraded() bool {
	return atomic.LoadInt32(&t.isDegraded) == 1
}

// SetDegraded allows forcing the degraded state (e.g. from rate limiter outage callback).
func (t *DegradedModeTracker) SetDegraded(degraded bool) {
	if degraded {
		atomic.StoreInt32(&t.isDegraded, 1)
	} else {
		atomic.StoreInt32(&t.isDegraded, 0)
	}
}

// DegradedModeHeader returns Fiber middleware that injects X-Authn-Degraded-Mode header dynamically.
func DegradedModeHeader(tracker *DegradedModeTracker) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if tracker != nil && tracker.IsDegraded() {
			c.Set("X-Authn-Degraded-Mode", "true")
		} else {
			c.Set("X-Authn-Degraded-Mode", "false")
		}
		return c.Next()
	}
}
