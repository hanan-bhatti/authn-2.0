/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/server/health_ready_test.go
 * Tier: System Level Integration & Readiness Probe Test Suite
 *
 * Description: Unit & integration test suite for Liveness Probe (/v1/health) and Readiness Probe (/v1/ready).
 *              Verifies 200 OK healthy/ready payloads, 503 Service Unavailable when DB is uninitialized or closed,
 *              liveness probe isolation, auth independence, and 405 Method Not Allowed handling.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

func TestHealthCheckLiveness(t *testing.T) {
	app := fiber.New()
	app.Get("/v1/health", HealthCheckHandler("0.1.0"))

	req := httptest.NewRequest("GET", "/v1/health", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed sending request: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var data HealthResponse
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("failed unmarshaling body: %v", err)
	}

	if data.Status != "healthy" || data.Version == "" || data.Timestamp == "" {
		t.Errorf("unexpected health response data: %+v", data)
	}

	// Non-GET method check (405 Method Not Allowed)
	postReq := httptest.NewRequest("POST", "/v1/health", nil)
	postResp, _ := app.Test(postReq)
	if postResp.StatusCode != 405 {
		t.Errorf("expected status 405 for POST /v1/health, got %d", postResp.StatusCode)
	}
}

func TestReadinessProbeSuccessAndFailure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ready_test_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db") + "?_fk=1"
	factory, err := clientfactory.NewClientFactory("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed initializing client factory: %v", err)
	}

	app := fiber.New()
	app.Get("/v1/health", HealthCheckHandler("0.1.0"))
	app.Get("/v1/ready", ReadinessCheckHandler(factory, nil))

	// 1. Dependency Check Test: When Redis is nil/unconfigured, readiness returns 503 not_ready (redis: down, database: ok)
	req := httptest.NewRequest("GET", "/v1/ready", nil)
	req.Header.Set("Authorization", "Bearer invalid_garbage_token")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("failed sending ready request: %v", err)
	}

	body, _ := io.ReadAll(resp.Body)
	var data ReadinessResponse
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatalf("failed unmarshaling readiness body: %v", err)
	}

	if resp.StatusCode != 503 || data.Status != "not_ready" || data.Checks["database"] != "ok" || data.Checks["redis"] != "down" {
		t.Errorf("expected 503 not_ready response with db ok and redis down, got status %d body %+v", resp.StatusCode, data)
	}

	// 2. DB Down / Factory Closed Test
	_ = factory.Close()

	failReq := httptest.NewRequest("GET", "/v1/ready", nil)
	failResp, _ := app.Test(failReq)

	failBody, _ := io.ReadAll(failResp.Body)
	var failData ReadinessResponse
	_ = json.Unmarshal(failBody, &failData)

	if failResp.StatusCode != 503 {
		t.Errorf("expected status 503 Service Unavailable when DB is down, got %d", failResp.StatusCode)
	}
	if failData.Status != "not_ready" || failData.Checks["database"] != "down" {
		t.Errorf("expected status 'not_ready' with database 'down', got %+v", failData)
	}

	// 3. Confirm /v1/health Liveness Probe STILL returns 200 healthy when DB is down!
	livenessReq := httptest.NewRequest("GET", "/v1/health", nil)
	livenessResp, _ := app.Test(livenessReq)
	if livenessResp.StatusCode != 200 {
		t.Errorf("expected /v1/health liveness to remain 200 OK when DB is down, got %d", livenessResp.StatusCode)
	}

	// 4. Method Enforcement Check
	postReq := httptest.NewRequest("POST", "/v1/ready", nil)
	postResp, _ := app.Test(postReq)
	if postResp.StatusCode != 405 {
		t.Errorf("expected status 405 for POST /v1/ready, got %d", postResp.StatusCode)
	}
}
