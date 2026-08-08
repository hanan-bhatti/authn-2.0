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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/impersonation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/org"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/social"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/database"
	"github.com/redis/go-redis/v9"
)

// HealthResponse represents the standard JSON payload returned by the health check endpoint.
type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	Version   string `json:"version" example:"1.0.0"`
	Timestamp string `json:"timestamp" example:"2026-08-01T16:55:00Z"`
}

type ReadinessResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// HealthCheckHandler handles engine health check requests (liveness probe).
func HealthCheckHandler(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(HealthResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// ReadinessCheckHandler handles engine readiness check requests (dependency connectivity probe).
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

// statusToCode maps an HTTP status reaching the global ErrorHandler onto a
// machine-readable error code. Only 4xx statuses land here — 5xx is routed
// through httperr.SendInternal.
//
// The statuses Fiber raises itself (404 from the router, 405, 413, 415) have no
// constant in httperr because no handler produces them; they are spelled out as
// literals rather than collapsed into an existing constant, so a client never
// sees "invalid_request_body" for what was actually a routing miss.
func statusToCode(status int) httperr.Code {
	switch status {
	case fiber.StatusBadRequest:
		return httperr.CodeInvalidRequestBody
	case fiber.StatusUnauthorized:
		return httperr.CodeUnauthorized
	case fiber.StatusForbidden:
		return httperr.CodeForbidden
	case fiber.StatusNotFound:
		return httperr.CodeNotFound
	case fiber.StatusConflict:
		return httperr.CodeConflict
	case fiber.StatusUnprocessableEntity:
		return httperr.CodeValidationFailed
	case fiber.StatusTooManyRequests:
		return httperr.CodeRateLimited
	case fiber.StatusMethodNotAllowed:
		return "method_not_allowed"
	case fiber.StatusRequestEntityTooLarge:
		return "payload_too_large"
	case fiber.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	default:
		return "bad_request"
	}
}

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

func main() {
	log.Println("🚀 Authn Platform — Enterprise Identity Engine v1.0.0 starting...")

	// 1. Load and validate configuration.
	//
	// A configuration error is fatal in every environment. Falling back to
	// built-in defaults would start the server in a state nobody chose, using
	// secrets committed to source — the exact situation the validation exists
	// to prevent. The error names every variable at fault.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error:\n%v", err)
	}
	log.Printf("configuration loaded: env=%s listen=%s database=%s",
		cfg.Env, cfg.Address(), database.DescribeURL(cfg.DatabaseURL))

	// 2. Open the database. The URL's scheme selects the engine and driver, so
	// PostgreSQL, MySQL and SQLite all work with no code change here.
	factory, err := clientfactory.NewFromURL(cfg.DatabaseURL, clientfactory.PoolOptions{
		MaxOpenConns:    cfg.DatabaseMaxOpenConns,
		MaxIdleConns:    cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime: cfg.DatabaseConnMaxLifetime,
		AutoMigrate:     cfg.DatabaseAutoMigrate,
	})
	if err != nil {
		log.Fatalf("database initialization failed: %v", err)
	}
	defer factory.Close()

	// 3. Initialize Fiber Application
	app := fiber.New(fiber.Config{
		AppName:               "Authn Engine v1.0.0",
		DisableStartupMessage: false,
		// Timeouts bound how long a single connection may occupy a worker.
		// Without them a slow or stalled client holds a connection open
		// indefinitely, and enough of those exhaust the server.
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
		BodyLimit:    cfg.BodyLimit,
		// ProxyHeader makes c.IP() read the forwarded client address. It is
		// enabled only when a trusted proxy sits in front, because a client can
		// forge the header and would otherwise mint a fresh IP per request to
		// escape every per-IP rate limit.
		ProxyHeader: proxyHeader(cfg),
		// Last-resort handler for errors that reach Fiber unhandled: panics
		// recovered by recover.New, router 404s, body-limit and parser failures.
		//
		// This used to emit a NESTED body with an INTEGER code —
		// {"error": {"code": 500, "message": err.Error()}} — the only nested
		// envelope in the engine, and one that returned raw Go error text to
		// unauthenticated callers (audit finding M9). A panic inside a handler
		// surfaced its message, and Ent/SQL errors surfaced table and column
		// names. It is now the canonical flat {error, code} envelope, and the
		// error text is logged server-side instead of returned.
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}

			// 5xx means something genuinely broke and the text is ours, not the
			// caller's — log it and return the generic body. SendInternal does
			// both, and forces the status to 500, which is already correct here.
			if code >= fiber.StatusInternalServerError {
				return httperr.SendInternal(c, "fiber.unhandled", err)
			}

			// 4xx is a client-shaped failure. *fiber.Error messages at this level
			// are Fiber's own static strings ("Not Found", "Method Not Allowed",
			// "Request Entity Too Large"), so they are safe to return — but only
			// for the *fiber.Error case. Any other error type reaching here with
			// a 4xx status is not a vetted string, so it gets the generic text.
			msg := "request could not be processed"
			if e, ok := err.(*fiber.Error); ok {
				msg = e.Message
			}
			return httperr.Send(c, code, statusToCode(code), msg)
		},
	})

	// 4. Initialize Redis & Degraded Mode Health Tracker
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
		} else {
			log.Printf("⚡ Connected to Redis at %s", cfg.RedisURL)
		}
	}

	degradedTracker := middleware.NewDegradedModeTracker(redisClient, 1*time.Second)

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
	rateLimiter := ratelimit.NewLimiter(ratelimit.Options{
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
	resendLimiter := ratelimit.NewLimiter(ratelimit.Options{
		Redis:              redisClient,
		Enabled:            cfg.ResendRateLimitEnabled,
		FailClosed:         cfg.RateLimitFailClosed,
		MaxAttempts:        cfg.ResendRateLimitMaxAttempts,
		Window:             cfg.ResendRateLimitWindow,
		IPBudgetMultiplier: cfg.RateLimitIPBudgetMultiplier,
		BackoffSchedule:    cfg.RateLimitBackoffSchedule,
		ViolationReset:     violationReset,
	})

	apiKeyRepo := apikey.NewRepository(factory)
	apiKeyService := apikey.NewService(apiKeyRepo, cfg.APIKeyPepper)
	apiKeyHandler := apikey.NewHandler(apiKeyService)
	pkMiddleware := middleware.RequirePublishableKey(apiKeyService)
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
	authHandler := auth.NewHandler(authService, policyRepo, rateLimiter, resendLimiter)

	// adminMiddleware accepts EITHER sk_... secret key (backend servers / SDKs)
	// OR a JWT with role=tenant_admin (Authn web console browser sessions).
	// Checks mandatory 2FA on console admin JWT sessions.
	adminMiddleware := middleware.RequireAdminAuth(apiKeyService, cfg.EncryptionKey, authRepo)

	oauthRepo := oauth.NewRepository()
	oauthService := oauth.NewService(oauthRepo, authRepo, authService, cfg)
	oauthHandler := oauth.NewHandler(oauthService)

	socialRepo := social.NewRepository(factory, cfg.EncryptionKey)
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
	webhookDispatcher := webhook.NewDispatcher(webhookRepo, cfg.EncryptionKey, 5)
	webhookDispatcher.Start()
	defer webhookDispatcher.Stop()
	webhookService := webhook.NewService(webhookRepo, webhookDispatcher, cfg)
	webhookHandler := webhook.NewHandler(webhookService)

	impersonationService := impersonation.NewService(factory, cfg, webhookDispatcher, emailProvider, rbacService)
	impersonationHandler := impersonation.NewHandler(impersonationService, policyRepo, authService)

	orgService := org.NewService(factory, webhookDispatcher)
	orgHandler := org.NewHandler(orgService)

	samlService := saml.NewService(factory, webhookDispatcher)
	samlHandler := saml.NewHandler(samlService)

	userService := user.NewService(authRepo, emailProvider, policyRepo, webhookDispatcher)
	userHandler := user.NewHandler(userService)
	clientAuthMiddleware := middleware.RequireClientAuth(cfg.EncryptionKey)

	// 6. System & Feature Routes
	app.Get("/v1/health", HealthCheckHandler)
	app.Get("/v1/ready", ReadinessCheckHandler(factory, redisClient))
	app.Get("/healthz", HealthCheckHandler)
	app.Get("/readyz", ReadinessCheckHandler(factory, redisClient))
	app.Use("/v1/client", middleware.PreventImpersonatedMutations(cfg.EncryptionKey))
	authHandler.RegisterRoutes(app, pkMiddleware)
	userHandler.RegisterRoutes(app, clientAuthMiddleware, pkMiddleware)
	policyHandler.RegisterRoutes(app, adminMiddleware) // sk_ OR console JWT
	oauthHandler.RegisterRoutes(app, pkMiddleware, adminMiddleware)
	socialHandler.RegisterRoutes(app, pkMiddleware, adminMiddleware)
	sessionHandler.RegisterRoutes(app, pkMiddleware, adminMiddleware)
	apiKeyHandler.RegisterRoutes(app, adminMiddleware) // sk_ OR console JWT
	rbacHandler.RegisterRoutes(app, adminMiddleware, clientAuthMiddleware, pkMiddleware)
	webhookHandler.RegisterRoutes(app, adminMiddleware)
	impersonationHandler.RegisterRoutes(app, adminMiddleware, clientAuthMiddleware, pkMiddleware)
	orgHandler.RegisterRoutes(app, clientAuthMiddleware, pkMiddleware, adminMiddleware)
	samlHandler.RegisterRoutes(app, pkMiddleware, adminMiddleware)

	// 6. Graceful Shutdown Listener
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		addr := cfg.Address()
		log.Printf("HTTP server listening on %s", addr)
		if err := app.Listen(addr); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-stop
	log.Println("🛑 Shutting down Authn Engine server gracefully...")
	if err := app.Shutdown(); err != nil {
		log.Printf("⚠️ Error shutting down server: %v", err)
	}
	log.Println("👋 Authn Engine server stopped cleanly.")
}
