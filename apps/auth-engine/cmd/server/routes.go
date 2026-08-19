/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/server/routes.go
 * Tier: Server Entrypoint & HTTP Bootstrapper
 *
 * Description: Registration of health check probes, system endpoints, and feature routes.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/redis/go-redis/v9"
)

// registerRoutes registers system probes, global route middleware, and feature route handlers onto Fiber.
func registerRoutes(
	app *fiber.App,
	cfg *config.Config,
	factory *clientfactory.ClientFactory,
	redisClient *redis.Client,
	w *appWiring,
) {
	bl := tokenblocklist.New(redisClient)
	// 6. System & Feature Routes
	app.Get("/v1/health", HealthCheckHandler(cfg.AppVersion))
	app.Get("/v1/ready", ReadinessCheckHandler(factory, redisClient))
	app.Get("/healthz", HealthCheckHandler(cfg.AppVersion))
	app.Get("/readyz", ReadinessCheckHandler(factory, redisClient))
	app.Use("/v1/client", middleware.PreventImpersonatedMutations(cfg.EncryptionKey, bl))
	w.authHandler.RegisterRoutes(app, w.pkMiddleware)
	w.userHandler.RegisterRoutes(app, w.clientAuthMiddleware, w.pkMiddleware)
	w.policyHandler.RegisterRoutes(app, w.adminMiddleware) // sk_ OR console JWT
	// pk_ for the public bootstrap document, sk_ OR console JWT for branding.
	w.appConfigHandler.RegisterRoutes(app, w.pkMiddleware, w.adminMiddleware)
	w.oauthHandler.RegisterRoutes(app, w.pkMiddleware, w.adminMiddleware)
	w.socialHandler.RegisterRoutes(app, w.pkMiddleware, w.adminMiddleware)
	w.sessionHandler.RegisterRoutes(app, w.pkMiddleware, w.adminMiddleware)
	w.apiKeyHandler.RegisterRoutes(app, w.adminMiddleware) // sk_ OR console JWT
	w.rbacHandler.RegisterRoutes(app, w.adminMiddleware, w.clientAuthMiddleware, w.pkMiddleware)
	w.webhookHandler.RegisterRoutes(app, w.adminMiddleware)
	w.impersonationHandler.RegisterRoutes(app, w.adminMiddleware, w.clientAuthMiddleware, w.pkMiddleware)
	w.orgHandler.RegisterRoutes(app, w.clientAuthMiddleware, w.pkMiddleware, w.adminMiddleware)
	w.samlHandler.RegisterRoutes(app, w.pkMiddleware, w.adminMiddleware)
	w.auditHandler.RegisterRoutes(app, w.adminMiddleware)
	w.userAdminHandler.RegisterRoutes(app, w.adminMiddleware)
	// The inbox refuses a live credential from inside the handler rather than by
	// mounting differently, so an operator holding the wrong key is told which
	// environment they are addressing instead of reading an empty inbox.
	w.sandboxHandler.RegisterRoutes(app, w.adminMiddleware)
	// Nil when no platform tenant is configured, in which case nothing mounts and
	// /v1/platform is a plain 404.
	w.platformHandler.RegisterRoutes(app, w.platformMiddleware)
}
