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
	"context"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/appconfig"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/audit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/authcookie"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/impersonation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/oauth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/org"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/platform"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/provisioning"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/retention"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/saml"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sandbox"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/settings"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/social"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/useradmin"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/redis/go-redis/v9"
)

type appWiring struct {
	pkMiddleware         fiber.Handler
	clientAuthMiddleware fiber.Handler
	adminMiddleware      fiber.Handler
	// platformMiddleware is nil when no platform tenant is configured, which
	// leaves the control-plane routes unregistered.
	platformMiddleware   fiber.Handler
	authHandler          *auth.Handler
	userHandler          *user.Handler
	policyHandler        *policy.Handler
	appConfigHandler     *appconfig.Handler
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
	userAdminHandler     *useradmin.Handler
	sandboxHandler       *sandbox.Handler
	platformHandler      *platform.Handler
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

	// settingsResolver is the live source of per-tenant session policy and
	// per-application settings, cached in Redis under a short TTL.
	//
	// A nil redisClient — REDIS_REQUIRED=false with Redis unavailable — reads
	// through to the database on every call, trading latency for availability.
	settingsResolver := settings.NewResolver(factory, policyRepo, redisClient, 0)
	policyHandler = policyHandler.WithSettingsInvalidator(settingsResolver)

	// tokenTTL answers "how long should this tenant's tokens last" for every service
	// that signs an access token or opens a session, resolving the tenant's own
	// choice and bounding it by the deployment ceiling.
	//
	// It is a cookie writer because that type already computes both answers for the
	// cookies it writes. Handing the same object to the services is what keeps a
	// token and the cookie carrying it from disagreeing: one implementation, one
	// ceiling, one policy read. It matters most for the refresh lifetime, where the
	// cookie is only advice to a browser and the session row is the enforcement — a
	// tenant shortening its window needs the row to agree, or the shortening applies
	// to nobody holding the raw token. The handlers below build their own writers
	// over the same resolver for the cookies themselves.
	tokenTTL := authcookie.NewWriter(cfg, settingsResolver)

	// The bootstrap document a sign-in page fetches before it renders. It reuses
	// the settings resolver's cache for the application lookup, because this is the
	// one request every page load makes ahead of everything else.
	appConfigHandler := appconfig.NewHandler(
		appconfig.NewService(appconfig.NewRepository(factory), policyRepo, settingsResolver, cfg),
	)

	// The sandbox store is built before the providers so both can be wrapped
	// before any service takes a reference to one.
	sandboxStore := sandbox.NewStore(factory)

	directEmail, err := email.NewEmailProvider(cfg)
	if err != nil {
		log.Printf("email: provider initialization failed: %v; falling back to noop (messages are logged, not sent)", err)
		directEmail = email.NewNoopProvider()
	} else {
		log.Printf("email: driver=%s from=%s", cfg.EmailDriver, cfg.EmailFromAddress)
	}

	directSMS, err := sms.NewSMSProvider(cfg)
	if err != nil {
		log.Printf("sms: provider initialization failed: %v; falling back to noop (messages are logged, not sent)", err)
		directSMS = sms.NewNoopProvider()
	} else {
		log.Printf("sms: driver=%s", cfg.SMSDriver)
	}

	// emailProvider and smsProvider capture rather than deliver when the sender is
	// acting in the test environment, and every service below is given these
	// rather than the direct ones.
	//
	// Wrapping once here is what makes the sandbox cover every sender the engine
	// has, including ones added later: a send site nobody remembered to route
	// through the sandbox is a real message leaving a test environment, addressed
	// to whoever a fixture named. The direct providers survive under their own
	// names for the one endpoint whose purpose is to reach a provider.
	emailProvider := sandbox.WrapEmail(directEmail, sandboxStore)
	smsProvider := sandbox.WrapSMS(directSMS, sandboxStore)

	// Delivery verification borrows the resend limiter, which already exists to
	// bound sends that cost money per message.
	sandboxHandler := sandbox.NewHandler(sandboxStore, factory, cfg, directEmail, directSMS).
		WithLimiter(resendLimiter)

	// The dispatcher is built before the services that publish through it. Its
	// workers are started here rather than at the end of wiring because there is
	// nothing to deliver until the first request arrives, and every service below
	// needs the handle.
	webhookRepo := webhook.NewRepository(factory)
	webhookDispatcher := webhook.NewDispatcher(webhookRepo, cfg.EncryptionKey, cfg.WebhookWorkerCount)
	webhookDispatcher.Start()

	authRepo := auth.NewRepository(factory)
	authService := auth.NewService(authRepo, cfg, emailProvider, smsProvider).
		WithWebhooks(webhookDispatcher).
		WithTokenTTLResolver(tokenTTL)
	authHandler := auth.NewHandler(authService, policyRepo, rateLimiter, resendLimiter).
		WithBlocklist(bl).
		WithSessionPolicyResolver(settingsResolver)

	// adminMiddleware accepts EITHER sk_... secret key (backend servers / SDKs)
	// OR a JWT with role=tenant_admin (Authn web console browser sessions).
	// Checks mandatory 2FA on console admin JWT sessions.
	adminMiddleware := middleware.RequireAdminAuth(apiKeyService, cfg.EncryptionKey, bl, authRepo)

	oauthRepo := oauth.NewRepository()
	oauthService := oauth.NewService(oauthRepo, authRepo, authService, cfg).
		WithAccessTokenTTLResolver(tokenTTL)
	oauthHandler := oauth.NewHandler(oauthService).WithSettings(settingsResolver)

	sessionRepo := session.NewRepository(factory)
	sessionService := session.NewService(sessionRepo, cfg).
		WithWebhooks(webhookDispatcher).
		WithTokenTTLResolver(tokenTTL)
	sessionHandler := session.NewHandler(sessionService).WithSessionPolicyResolver(settingsResolver)

	// Social sign-in issues its session through the same store the session
	// endpoints read, so a Google login is listed and revoked like any other.
	socialRepo := social.NewRepository(factory, policyRepo, cfg.EncryptionKey)
	socialService := social.NewService(socialRepo, cfg, sessionRepo).
		WithWebhooks(webhookDispatcher).
		WithTokenTTLResolver(tokenTTL)
	socialHandler := social.NewHandler(socialService).
		WithSessionPolicyResolver(settingsResolver)

	rbacRepo := rbac.NewRepository(factory)
	rbacAudit := rbac.NewAuditLogger(factory)
	rbacService := rbac.NewService(rbacRepo, rbacAudit, cfg).
		WithWebhooks(webhookDispatcher)
	rbacHandler := rbac.NewHandler(rbacService)

	webhookService := webhook.NewService(webhookRepo, webhookDispatcher, cfg)
	webhookHandler := webhook.NewHandler(webhookService)

	impersonationService := impersonation.NewService(factory, cfg, webhookDispatcher, emailProvider, rbacService)
	impersonationHandler := impersonation.NewHandler(impersonationService, policyRepo, authService, bl)

	orgService := org.NewService(factory, webhookDispatcher, cfg)
	orgHandler := org.NewHandler(orgService)

	// Enterprise SSO issues its session through the same store the session
	// endpoints read, so an Okta login is listed and revoked like any other.
	samlService := saml.NewService(factory, webhookDispatcher, sessionRepo, cfg).
		WithTokenTTLResolver(tokenTTL)
	samlHandler := saml.NewHandler(samlService).
		WithSessionPolicyResolver(settingsResolver)

	userService := user.NewService(authRepo, emailProvider, policyRepo, webhookDispatcher, cfg)
	userHandler := user.NewHandler(userService)
	clientAuthMiddleware := middleware.RequireClientAuth(cfg.EncryptionKey, bl)

	auditHandler := audit.NewHandler(factory)

	// User administration shares the session repository and the token blocklist
	// with the authentication path, because restricting an account has to reach
	// the sessions and the access tokens that path issued.
	userAdminService := useradmin.NewService(useradmin.NewRepository(factory), sessionRepo, bl, cfg).
		WithWebhooks(webhookDispatcher)
	userAdminHandler := useradmin.NewHandler(userAdminService)

	// The hosted control plane exists only where a platform tenant is configured.
	// Leaving the middleware nil in an OSS deployment leaves the routes
	// unregistered, so /v1/platform answers 404 rather than advertising a surface
	// that has no tenant to serve.
	var platformMiddleware fiber.Handler
	if cfg.PlatformTenantID != "" {
		platformMiddleware = middleware.RequirePlatformAuth(cfg.EncryptionKey, cfg.PlatformTenantID, bl, authRepo)
	}
	provisioningService := provisioning.NewService(factory, apiKeyService)
	platformHandler := platform.NewHandler(provisioningService, platform.NewRepository(factory),
		rateLimiter, cfg.PlatformTenantSlug)

	sweeper := newRetentionSweeper(cfg, redisClient, authRepo, policyRepo, sessionRepo, socialRepo, sandboxStore)
	sweeper.Start()

	return &appWiring{
		pkMiddleware:         pkMiddleware,
		clientAuthMiddleware: clientAuthMiddleware,
		adminMiddleware:      adminMiddleware,
		platformMiddleware:   platformMiddleware,
		authHandler:          authHandler,
		userHandler:          userHandler,
		policyHandler:        policyHandler,
		appConfigHandler:     appConfigHandler,
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
		userAdminHandler:     userAdminHandler,
		sandboxHandler:       sandboxHandler,
		platformHandler:      platformHandler,
		cleanup: func() {
			webhookDispatcher.Stop()
			sweeper.Stop()
		},
	}
}

// newRetentionSweeper registers every table's retention rule with the background
// scheduler.
//
// The cutoffs are computed inside each task rather than here, so that a process
// running for weeks keeps sweeping against the current time instead of against
// its own start time.
func newRetentionSweeper(
	cfg *config.Config,
	redisClient *redis.Client,
	authRepo *auth.Repository,
	policyRepo *policy.Repository,
	sessionRepo *session.Repository,
	socialRepo *social.Repository,
	sandboxStore *sandbox.Store,
) *retention.Sweeper {
	// The telemetry sweep needs a service to hang off, and this one is
	// purge-only: the device-token key it also carries is unused by that path.
	telemetry := auth.NewTelemetryService(authRepo, cfg.EncryptionKey, policyRepo)

	return retention.New(cfg.RetentionSweepInterval, redisClient,
		retention.Task{
			Name: "sessions",
			Run: func(ctx context.Context) (int, error) {
				now := time.Now()
				return sessionRepo.PurgeExpiredSessions(
					ctx,
					now.Add(-cfg.SupersededSessionRetention),
					now.Add(-cfg.TerminalSessionRetention),
					cfg.RetentionBatchSize,
				)
			},
		},
		retention.Task{
			Name: "social auth state",
			Run: func(ctx context.Context) (int, error) {
				return socialRepo.PurgeExpiredAuthState(ctx, time.Now(), cfg.RetentionBatchSize)
			},
		},
		// Subnet history and trusted devices are written once per device or
		// network per user rather than once per request, and both sweep predicates
		// are indexed, so this one deletes in a single statement.
		retention.Task{
			Name: "device telemetry",
			Run: func(ctx context.Context) (int, error) {
				subnets, devices, err := telemetry.PurgeExpiredTelemetry(ctx)
				return subnets + devices, err
			},
		},
		// Captured test-environment messages hold verification links and one-time
		// codes in plain text, so the window is short: a harness reads its message
		// within seconds of triggering it, and everything kept past that is an
		// archive of credentials that still work.
		retention.Task{
			Name: "sandbox messages",
			Run: func(ctx context.Context) (int, error) {
				return sandboxStore.PurgeExpired(
					ctx,
					time.Now().Add(-cfg.SandboxMessageRetention),
					cfg.RetentionBatchSize,
				)
			},
		},
		// This is what keeps the test-environment user ceiling from becoming a wall.
		// Suites create accounts by the thousand and abandon them, and a tenant that
		// reached its limit through months of accumulated runs would start failing
		// runs that have nothing wrong with them.
		retention.Task{
			Name: "idle test users",
			Run: func(ctx context.Context) (int, error) {
				return authRepo.PurgeIdleTestUsers(
					ctx,
					time.Now().Add(-cfg.TestUserRetention),
					cfg.RetentionBatchSize,
				)
			},
		},
	)
}
