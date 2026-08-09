/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/server/middleware.go
 * Tier: Server Entrypoint & HTTP Bootstrapper
 *
 * Description: Global Fiber middleware stack setup and rate limiter initialization.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/redis/go-redis/v9"
)

// proxyHeader returns the header Fiber should read the client IP from, or ""
// to use the connection's peer address.
//
// Returning "" is the safe default: X-Forwarded-For is trivially forged, so
// trusting it without a proxy in front lets a caller present a new source
// address on every request and slip past per-IP rate limits.
func proxyHeader(cfg *config.Config) string {
	if cfg.TrustProxyHeaders {
		return fiber.HeaderXForwardedFor
	}
	return ""
}

// setupMiddleware attaches global middleware (recover, logger, CORS, degraded mode header)
// to the Fiber app and constructs rate limiters.
func setupMiddleware(app *fiber.App, cfg *config.Config, redisClient *redis.Client) (rateLimiter *ratelimit.Limiter, resendLimiter *ratelimit.Limiter) {
	degradedTracker := middleware.NewDegradedModeTracker(redisClient, cfg.DegradedModeCheckInterval)

	// 5. Global Middleware Stack
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(middleware.CORS(cfg))
	app.Use(middleware.DegradedModeHeader(degradedTracker))

	if !cfg.RateLimitEnabled {
		log.Println("WARNING: rate limiting is disabled (RATELIMIT_ENABLED=false); authentication endpoints are un-throttled")
	} else {
		log.Printf("rate limiter: max_attempts=%d window=%s ip_multiplier=%d backoff=%v",
			cfg.RateLimitMaxAttempts, cfg.RateLimitWindow,
			cfg.RateLimitIPBudgetMultiplier, cfg.RateLimitBackoffSchedule)
	}

	violationReset := time.Duration(cfg.RateLimitViolationResetDays) * 24 * time.Hour

	// Guards credential-checking endpoints: login, token refresh, 2FA verification.
	rateLimiter = ratelimit.NewLimiter(ratelimit.Options{
		Redis:              redisClient,
		Enabled:            cfg.RateLimitEnabled,
		FailClosed:         cfg.RateLimitFailClosed,
		MaxAttempts:        cfg.RateLimitMaxAttempts,
		Window:             cfg.RateLimitWindow,
		IPBudgetMultiplier: cfg.RateLimitIPBudgetMultiplier,
		BackoffSchedule:    cfg.RateLimitBackoffSchedule,
		ViolationReset:     violationReset,
	})

	// Guards verification-email resends, which cost money and can be used to
	// spam a third party's inbox, so it carries a tighter budget of its own.
	resendLimiter = ratelimit.NewLimiter(ratelimit.Options{
		Redis:              redisClient,
		Enabled:            cfg.ResendRateLimitEnabled,
		FailClosed:         cfg.RateLimitFailClosed,
		MaxAttempts:        cfg.ResendRateLimitMaxAttempts,
		Window:             cfg.ResendRateLimitWindow,
		IPBudgetMultiplier: cfg.RateLimitIPBudgetMultiplier,
		BackoffSchedule:    cfg.RateLimitBackoffSchedule,
		ViolationReset:     violationReset,
	})

	return rateLimiter, resendLimiter
}
