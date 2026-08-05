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
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/social"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/redis/go-redis/v9"
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
	if cfg.DatabaseURL != "" && (strings.HasPrefix(cfg.DatabaseURL, "postgres://") || strings.HasPrefix(cfg.DatabaseURL, "postgresql://")) {
		driver = "postgres"
	}
	factory, err := clientfactory.NewClientFactory(driver, cfg.DatabaseURL)
	if err != nil {
		if driver == "postgres" && cfg.Env != "production" {
			log.Printf("⚠️ Postgres connection notice (%s): %v. Falling back to SQLite development database.", cfg.DatabaseURL, err)
			driver = "sqlite3"
			cfg.DatabaseURL = "file:authn.db?cache=shared&_fk=1"
			factory, err = clientfactory.NewClientFactory(driver, cfg.DatabaseURL)
		}
		if err != nil {
			log.Fatalf("❌ Failed initializing database client factory: %v", err)
		}
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
	isProd := cfg.Env == "production"

	var redisClient *redis.Client
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			opt = &redis.Options{
				Addr: cfg.RedisURL,
			}
		}
		redisClient = redis.NewClient(opt)
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			log.Printf("⚠️ Redis ping notice (%s): %v. Rate limiter running with dev fallback / fail-closed protection.", cfg.RedisURL, err)
			redisClient = nil
		} else {
			log.Printf("⚡ Connected to Redis at %s", cfg.RedisURL)
		}
	}

	if !cfg.RateLimitEnabled {
		log.Println("⚠️ LOUD WARNING: Rate limiting is DISABLED via AUTHN_RATELIMIT_ENABLED=false. Security boundaries are un-throttled!")
	} else {
		log.Printf("🛡️ Rate Limiter configuration loaded from .env: max_attempts=%d, window_seconds=%d, backoff_schedule=%v, reset_days=%d", cfg.RateLimitMaxAttempts, cfg.RateLimitWindowSeconds, cfg.RateLimitBackoffSchedule, cfg.RateLimitViolationResetDays)
	}

	rateLimiter := ratelimit.NewLimiter(
		redisClient,
		isProd,
		true, // failClosed
		cfg.RateLimitEnabled,
		cfg.RateLimitMaxAttempts,
		cfg.RateLimitWindowSeconds,
		cfg.RateLimitBackoffSchedule,
		cfg.RateLimitViolationResetDays,
	)

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeyService := apikey.NewService(apiKeyRepo, cfg.AuthnAPIKeyPepper)
	apiKeyHandler := apikey.NewHandler(apiKeyService)
	pkMiddleware := middleware.RequirePublishableKey(apiKeyService)
	// adminMiddleware accepts EITHER sk_... secret key (backend servers / SDKs)
	// OR a JWT with role=tenant_admin (Authn web console browser sessions).
	// This is the single auth gate for all /v1/tenant/* and /v1/admin/* routes.
	adminMiddleware := middleware.RequireAdminAuth(apiKeyService, cfg.AuthnEncryptionKey)

	policyRepo := policy.NewRepository(factory)
	policyHandler := policy.NewHandler(policyRepo)

	emailProvider, err := email.NewEmailProvider(cfg)
	if err != nil {
		log.Printf("⚠️ Email Provider warning: %v. Falling back to NoopProvider.", err)
		emailProvider = email.NewNoopProvider()
	} else {
		log.Printf("📧 Email Provider initialized: %s (driver: %s, from: %s)", strings.ToUpper(cfg.EmailDriver), cfg.EmailDriver, cfg.EmailFromAddress)
	}

	authRepo := auth.NewRepository(factory)
	authService := auth.NewService(authRepo, cfg, emailProvider)
	authHandler := auth.NewHandler(authService, policyRepo, rateLimiter)

	ctx := privacy.NewBypassContext(context.Background())
	if err := authRepo.EnsureTenantExists(ctx, "tnt_default"); err != nil {
		log.Printf("⚠️ Default tenant initialization notice: %v", err)
	}
	if err := authRepo.EnsureDefaultApplicationExists(ctx, "app_test123", "tnt_default", []string{"http://localhost:3000/callback"}); err != nil {
		log.Printf("⚠️ Default application seeding notice: %v", err)
	}
	// Seed Tenant A (Default) Publishable Key & Secret Key
	defaultPK := "pk_test_demo12345678901234567890123456789012"
	defaultSK := "sk_test_demo12345678901234567890123456789012"
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_test_demo123", "app_test123", defaultPK, cfg.AuthnAPIKeyPepper); err == nil {
		log.Printf("🔑 Seeded Tenant A publishable key for verification: %s", defaultPK)
	}
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_test_sk_demo123_v3", "app_test123", defaultSK, cfg.AuthnAPIKeyPepper); err == nil {
		log.Printf("🔑 Seeded Tenant A secret key for verification: %s", defaultSK)
	} else {
		log.Printf("⚠️ Secret key seeding error: %v", err)
	}

	// Seed Tenant B, Application B, & Key B for cross-tenant HTTP isolation verification
	if err := authRepo.EnsureTenantExists(ctx, "tnt_tenantB"); err == nil {
		_ = authRepo.EnsureDefaultApplicationExists(ctx, "app_tenantB", "tnt_tenantB", []string{"http://localhost:3000/callback"})
		tenantBPK := "pk_test_tenantB_9999999999999999999999999999"
		tenantBSK := "sk_test_tenantB_9999999999999999999999999999"
		_ = apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_tenantB_123", "app_tenantB", tenantBPK, cfg.AuthnAPIKeyPepper)
		_ = apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_tenantB_sk_123_v2", "app_tenantB", tenantBSK, cfg.AuthnAPIKeyPepper)
	}

	oauthRepo := oauth.NewRepository()
	oauthService := oauth.NewService(oauthRepo, authRepo, authService, cfg)
	oauthHandler := oauth.NewHandler(oauthService)

	socialRepo := social.NewRepository(factory, cfg.AuthnEncryptionKey)
	socialService := social.NewService(socialRepo, cfg)
	socialHandler := social.NewHandler(socialService)

	sessionRepo := session.NewRepository(factory)
	sessionService := session.NewService(sessionRepo, cfg)
	sessionHandler := session.NewHandler(sessionService)

	rbacRepo := rbac.NewRepository(factory)
	rbacAudit := rbac.NewAuditLogger(factory)
	rbacService := rbac.NewService(rbacRepo, rbacAudit, cfg)
	rbacHandler := rbac.NewHandler(rbacService)

	webhookRepo := webhook.NewRepository(factory)
	webhookDispatcher := webhook.NewDispatcher(webhookRepo, cfg.AuthnEncryptionKey, 5)
	webhookDispatcher.Start()
	defer webhookDispatcher.Stop()
	webhookService := webhook.NewService(webhookRepo, webhookDispatcher, cfg)
	webhookHandler := webhook.NewHandler(webhookService)

	// 6. System & Feature Routes
	app.Get("/v1/health", HealthCheckHandler)
	authHandler.RegisterRoutes(app, pkMiddleware)
	policyHandler.RegisterRoutes(app, adminMiddleware) // sk_ OR console JWT
	oauthHandler.RegisterRoutes(app, pkMiddleware)
	socialHandler.RegisterRoutes(app, pkMiddleware, adminMiddleware)
	sessionHandler.RegisterRoutes(app, pkMiddleware, adminMiddleware)
	apiKeyHandler.RegisterRoutes(app, adminMiddleware) // sk_ OR console JWT
	rbacHandler.RegisterRoutes(app, adminMiddleware, pkMiddleware)
	webhookHandler.RegisterRoutes(app, adminMiddleware)

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
