/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/server/health.go
 * Tier: Server Entrypoint & HTTP Bootstrapper
 *
 * Description: Health and readiness handlers for process liveness and dependency checks.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/redis/go-redis/v9"
)

// HealthResponse is the JSON payload returned by the liveness endpoint.
type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	Version   string `json:"version" example:"0.1.0"`
	Timestamp string `json:"timestamp" example:"2026-08-01T16:55:00Z"`
}

// ReadinessResponse is the JSON payload returned by the readiness endpoint. It
// carries a per-dependency verdict so an operator can tell which backing
// service is at fault without reading the server's logs.
type ReadinessResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// HealthCheckHandler answers the liveness probe.
//
// It reports only that the process is running and serving HTTP; it deliberately
// touches no dependency, so a database outage does not cause the orchestrator to
// kill and restart otherwise healthy instances. Readiness is where dependencies
// are checked.
func HealthCheckHandler(version string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(HealthResponse{
			Status:    "healthy",
			Version:   version,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// ReadinessCheckHandler returns a handler answering the readiness probe.
//
// It pings the database and Redis and reports "ready" with 200 only when both
// answer, otherwise "not_ready" with 503 and a per-dependency verdict. A 503
// takes the instance out of the load balancer's rotation rather than killing
// it, so an instance whose database briefly went away stops receiving traffic
// and rejoins when the check passes again.
//
// Each ping is bounded by a two-second timeout: a probe that hangs is worse
// than one that fails, because the orchestrator learns nothing while it waits.
func ReadinessCheckHandler(factory *clientfactory.ClientFactory, redisClient *redis.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
		defer cancel()

		dbStatus := "ok"
		if factory == nil || factory.Ping(ctx) != nil {
			dbStatus = "down"
		}

		redisStatus := "ok"
		if redisClient == nil || redisClient.Ping(ctx).Err() != nil {
			redisStatus = "down"
		}

		checks := map[string]string{
			"database": dbStatus,
			"redis":    redisStatus,
		}

		if dbStatus != "ok" || redisStatus != "ok" {
			return c.Status(fiber.StatusServiceUnavailable).JSON(ReadinessResponse{
				Status: "not_ready",
				Checks: checks,
			})
		}

		return c.Status(fiber.StatusOK).JSON(ReadinessResponse{
			Status: "ready",
			Checks: checks,
		})
	}
}
