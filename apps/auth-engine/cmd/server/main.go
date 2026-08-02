/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/server/main.go
 * Tier: Server Entrypoint & HTTP Bootstrapper
 *
 * Description: Primary entrypoint for the Go Fiber authentication engine HTTP/WSS server.
 *              Initializes configuration, Ent ClientFactory connection pools, Fiber middleware,
 *              and registers all feature routes.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// HealthResponse represents the standard JSON payload returned by the health check endpoint.
type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	Version   string `json:"version" example:"1.0.0"`
	Timestamp string `json:"timestamp" example:"2026-08-01T16:55:00Z"`
}

// HealthCheckHandler handles engine health check requests.
//
// @Summary Engine Health Check
// @Description Returns current operational health status of the Authn Go engine.
// @Tags System
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /v1/health [get]
func HealthCheckHandler(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(HealthResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

func main() {
	log.Println("🚀 Authn Platform — Enterprise Identity Engine v1.0.0 starting...")

	// 1. Pre-flight Environment Validation
	cfg, err := config.LoadAndValidateConfig()
	if err != nil {
		log.Printf("⚠️ Development fallback mode: %v", err)
		cfg = &config.EnvConfig{
			Port:               "8080",
			Env:                "development",
			DatabaseURL:        "file:authn.db?cache=shared&_fk=1",
			AuthnAPIKeyPepper:  "dev_pepper_key_32_bytes_long_123456",
			AuthnEncryptionKey: "dev_encryption_key_32_bytes_long_12345",
			AuthnKeyID:         "key_v1",
			Issuer:             "http://localhost:8080",
		}
	}

	// 2. Initialize Ent ORM ClientFactory
	driver := "sqlite3"
	if cfg.DatabaseURL != "" && cfg.DatabaseURL != "file:authn.db?cache=shared&_fk=1" {
		driver = "postgres"
	}
	factory, err := clientfactory.NewClientFactory(driver, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("❌ Failed initializing database client factory: %v", err)
	}
	defer factory.Close()

	// 3. Initialize Fiber Application
	app := fiber.New(fiber.Config{
		AppName:               "Authn Engine v1.0.0",
		DisableStartupMessage: false,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"error": fiber.Map{
					"code":    code,
					"message": err.Error(),
				},
			})
		},
	})

	// 4. Global Middleware Stack
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(middleware.DynamicCORS())
	app.Use(middleware.DegradedModeHeader(false))

	// 5. Initialize Feature Services & Handlers
	policyRepo := policy.NewRepository(factory)
	policyHandler := policy.NewHandler(policyRepo)

	authRepo := auth.NewRepository(factory)
	authService := auth.NewService(authRepo, cfg)
	authHandler := auth.NewHandler(authService, policyRepo)

	oauthRepo := oauth.NewRepository()
	oauthService := oauth.NewService(oauthRepo, cfg)
	oauthHandler := oauth.NewHandler(oauthService)

	// 6. System & Feature Routes
	app.Get("/v1/health", HealthCheckHandler)
	authHandler.RegisterRoutes(app)
	policyHandler.RegisterRoutes(app)
	oauthHandler.RegisterRoutes(app)

	// 6. Graceful Shutdown Listener
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		addr := fmt.Sprintf(":%s", cfg.Port)
		log.Printf("⚡ Authn Engine HTTP server listening on %s", addr)
		if err := app.Listen(addr); err != nil {
			log.Fatalf("❌ Server error: %v", err)
		}
	}()

	<-stop
	log.Println("🛑 Shutting down Authn Engine server gracefully...")
	if err := app.Shutdown(); err != nil {
		log.Printf("⚠️ Error shutting down server: %v", err)
	}
	log.Println("👋 Authn Engine server stopped cleanly.")
}
