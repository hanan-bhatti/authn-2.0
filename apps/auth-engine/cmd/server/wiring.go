/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/server/wiring.go
 * Tier: Server Entrypoint & HTTP Bootstrapper
 *
 * Description: Dependency injection and instantiation of repositories, services, and HTTP handlers.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/audit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/redis/go-redis/v9"
)

type appWiring struct {
	pkMiddleware         fiber.Handler
	clientAuthMiddleware fiber.Handler
	adminMiddleware      fiber.Handler
	authHandler          *auth.Handler
	userHandler          *user.Handler
	policyHandler        *policy.Handler
	oauthHandler         *oauth.Handler
	socialHandler        *social.Handler
	sessionHandler       *session.Handler
	apiKeyHandler        *apikey.Handler
	rbacHandler          *rbac.Handler
	webhookHandler       *webhook.Handler
	impersonationHandler *impersonation.Handler
	orgHandler           *org.Handler
	samlHandler          *saml.Handler
	auditHandler         *audit.Handler
	cleanup              func()
}

// wireFeatures instantiates repositories, services, and handlers for all features.
func wireFeatures(
	cfg *config.Config,
	factory *clientfactory.ClientFactory,
	rateLimiter *ratelimit.Limiter,
	resendLimiter *ratelimit.Limiter,
	redisClient *redis.Client,
) *appWiring {
	bl := tokenblocklist.New(redisClient)
	apiKeyRepo := apikey.NewRepository(factory)
	apiKeyService := apikey.NewService(apiKeyRepo, cfg.APIKeyPepper)
	apiKeyHandler := apikey.NewHandler(apiKeyService)
	pkMiddleware := middleware.RequirePublishableKey(apiKeyService)
	policyRepo := policy.NewRepository(factory)
	policyHandler := policy.NewHandler(policyRepo)

	emailProvider, err := email.NewEmailProvider(cfg)
	if err != nil {
		log.Printf("email: provider initialization failed: %v; falling back to noop (messages are logged, not sent)", err)
		emailProvider = email.NewNoopProvider()
	} else {
		log.Printf("email: driver=%s from=%s", cfg.EmailDriver, cfg.EmailFromAddress)
	}

	authRepo := auth.NewRepository(factory)
	authService := auth.NewService(authRepo, cfg, emailProvider)
	authHandler := auth.NewHandler(authService, policyRepo, rateLimiter, resendLimiter).WithBlocklist(bl)

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
	webhookDispatcher := webhook.NewDispatcher(webhookRepo, cfg.EncryptionKey, cfg.WebhookWorkerCount)
	webhookDispatcher.Start()
	webhookService := webhook.NewService(webhookRepo, webhookDispatcher, cfg)
	webhookHandler := webhook.NewHandler(webhookService)

	impersonationService := impersonation.NewService(factory, cfg, webhookDispatcher, emailProvider, rbacService)
	impersonationHandler := impersonation.NewHandler(impersonationService, policyRepo, authService, bl)

	orgService := org.NewService(factory, webhookDispatcher, cfg)
	orgHandler := org.NewHandler(orgService)

	samlService := saml.NewService(factory, webhookDispatcher, cfg)
	samlHandler := saml.NewHandler(samlService)

	userService := user.NewService(authRepo, emailProvider, policyRepo, webhookDispatcher, cfg)
	userHandler := user.NewHandler(userService)
	clientAuthMiddleware := middleware.RequireClientAuth(cfg.EncryptionKey, bl)

	auditHandler := audit.NewHandler(factory)

	return &appWiring{
		pkMiddleware:         pkMiddleware,
		clientAuthMiddleware: clientAuthMiddleware,
		adminMiddleware:      adminMiddleware,
		authHandler:          authHandler,
		userHandler:          userHandler,
		policyHandler:        policyHandler,
		oauthHandler:         oauthHandler,
		socialHandler:        socialHandler,
		sessionHandler:       sessionHandler,
		apiKeyHandler:        apiKeyHandler,
		rbacHandler:          rbacHandler,
		webhookHandler:       webhookHandler,
		impersonationHandler: impersonationHandler,
		orgHandler:           orgHandler,
		samlHandler:          samlHandler,
		auditHandler:         auditHandler,
		cleanup: func() {
			webhookDispatcher.Stop()
		},
	}
}
