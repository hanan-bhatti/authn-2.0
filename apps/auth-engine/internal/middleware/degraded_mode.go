/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/degraded_mode.go
 * Tier: HTTP Middleware Layer / Availability Signalling
 *
 * Redis health tracking and the X-Authn-Degraded-Mode response header.
 *
 * When Redis is unreachable the engine keeps serving — sessions stay valid and
 * reads fall back to the database — but caching and shared rate-limit state are
 * gone. The header tells client SDKs which of the two modes they are talking to
 * so they can adjust without a session ever breaking.
 *
 * Health is sampled by a background ticker and published through an atomic flag,
 * so a request reads one integer instead of paying a Redis round trip; the state
 * a request sees is at most one tick stale.
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

const (
	// defaultHealthCheckInterval is the sampling period used when the caller
	// supplies a non-positive interval. A zero interval would panic time.NewTicker,
	// so the constructor substitutes this rather than fail at startup.
	defaultHealthCheckInterval = 1 * time.Second

	// healthPingTimeout bounds a single Redis PING. It is short by design: an
	// unresponsive store is degraded for this purpose whether it is down or
	// merely too slow to be useful, and the ticker must not stack up goroutines
	// waiting on a hung socket.
	healthPingTimeout = 500 * time.Millisecond
)

// DegradedModeTracker samples Redis connectivity in the background and publishes
// the result for per-request reads at no latency cost. Its methods are safe for
// concurrent use.
type DegradedModeTracker struct {
	// redisClient is the connection under observation. Nil means permanently
	// degraded — the engine was started with no cache at all.
	redisClient *redis.Client
	// isDegraded is 1 when Redis is unreachable and 0 when healthy. Accessed
	// only through sync/atomic.
	isDegraded int32
	// stopChan is closed by Stop to end the background ticker.
	stopChan chan struct{}
}

// NewDegradedModeTracker returns a tracker that samples Redis health every
// checkInterval, substituting defaultHealthCheckInterval when that is
// non-positive.
//
// The first sample is taken synchronously, so the tracker never reports a
// healthy Redis it has not yet contacted. A nil client yields a tracker that is
// permanently degraded and starts no goroutine; Stop is still safe to call on it.
func NewDegradedModeTracker(redisClient *redis.Client, checkInterval time.Duration) *DegradedModeTracker {
	t := &DegradedModeTracker{
		redisClient: redisClient,
		stopChan:    make(chan struct{}),
	}

	if redisClient == nil {
		atomic.StoreInt32(&t.isDegraded, 1)
		return t
	}

	t.checkHealth()

	if checkInterval <= 0 {
		checkInterval = defaultHealthCheckInterval
	}
	go t.startTicker(checkInterval)

	return t
}

// checkHealth pings Redis and records the outcome in the degraded flag.
func (t *DegradedModeTracker) checkHealth() {
	if t.redisClient == nil {
		atomic.StoreInt32(&t.isDegraded, 1)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthPingTimeout)
	defer cancel()

	if err := t.redisClient.Ping(ctx).Err(); err != nil {
		atomic.StoreInt32(&t.isDegraded, 1)
	} else {
		atomic.StoreInt32(&t.isDegraded, 0)
	}
}

// startTicker samples health every interval until stopChan is closed.
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

// Stop ends the background health ticker. It must be called at most once.
func (t *DegradedModeTracker) Stop() {
	close(t.stopChan)
}

// IsDegraded reports whether Redis was unreachable as of the most recent sample.
func (t *DegradedModeTracker) IsDegraded() bool {
	return atomic.LoadInt32(&t.isDegraded) == 1
}

// SetDegraded forces the degraded flag, letting a component that has just seen
// Redis fail — the rate limiter, for instance — publish that immediately instead
// of waiting for the next tick. The next sample overwrites it.
func (t *DegradedModeTracker) SetDegraded(degraded bool) {
	if degraded {
		atomic.StoreInt32(&t.isDegraded, 1)
	} else {
		atomic.StoreInt32(&t.isDegraded, 0)
	}
}

// DegradedModeHeader returns a Fiber middleware that sets X-Authn-Degraded-Mode
// to "true" or "false" on every response. The header is always present, so a
// client can distinguish a degraded engine from an old one that does not report
// the state at all. A nil tracker reports healthy.
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
