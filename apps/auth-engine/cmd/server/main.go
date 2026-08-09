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
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/database"
	"github.com/redis/go-redis/v9"
)

// main starts the engine: it loads configuration, opens the database and
// Redis, wires every feature's repository, service and handler onto a Fiber
// app, and serves until a termination signal arrives.
//
// It exits non-zero on any startup failure. Configuration and database errors
// are fatal in every environment, because continuing would mean serving with
// settings nobody chose.
func main() {
	log.Println("authn engine starting")

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
		AppName:               cfg.AppName + " " + cfg.AppVersion,
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
		ProxyHeader:  proxyHeader(cfg),
		ErrorHandler: ErrorHandler,
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
			log.Printf("redis: unreachable at %s: %v; rate limiter falling back to in-process state or failing closed", cfg.RedisURL, err)
		} else {
			log.Printf("redis: connected at %s", cfg.RedisURL)
		}
	}

	// 5. Global Middleware & Rate Limiting Stack
	rateLimiter, resendLimiter := setupMiddleware(app, cfg, redisClient)

	// 6. Wire Repositories, Services, and Handlers
	wiring := wireFeatures(cfg, factory, rateLimiter, resendLimiter)
	defer wiring.cleanup()

	// 7. System & Feature Routes
	registerRoutes(app, cfg, factory, redisClient, wiring)

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
	log.Println("shutdown: signal received, draining in-flight requests")
	if err := app.Shutdown(); err != nil {
		log.Printf("shutdown: error draining server: %v", err)
	}
	log.Println("shutdown: server stopped")
}
