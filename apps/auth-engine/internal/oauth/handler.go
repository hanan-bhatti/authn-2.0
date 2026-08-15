/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/handler.go
 * Tier: Internal Feature Package / OAuth2 & OIDC HTTP Handlers
 *
 * Description: Fiber handlers for the OAuth2 and OpenID Connect endpoints —
 *              discovery, JWKS publication and rotation, the PKCE authorization
 *              endpoint, token exchange and refresh, UserInfo, and client
 *              application registration.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"github.com/gofiber/fiber/v2"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/authcookie"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/settings"
)

const (
	// refreshTokenCookieName is the canonical cookie the engine writes rotated
	// refresh tokens to.
	refreshTokenCookieName = authcookie.RefreshTokenName

	// metadataCacheControl is sent on the discovery and JWKS documents. Both are
	// public, change only on rotation, and are fetched by every relying party.
	metadataCacheControl = "public, max-age=3600"
)

// Handler exposes the OAuth2 and OIDC endpoints over HTTP.
type Handler struct {
	// service performs the underlying OAuth2 and OIDC operations.
	service *Service
	// cookies builds the rotated refresh cookie. Never nil: NewHandler installs a
	// writer backed by default tenant policy and WithSettings swaps in one that
	// reads live policy.
	cookies *authcookie.Writer
	// settings is the runtime-settings cache. It is nil until WithSettings wires
	// one, and every use is nil-checked: a missing resolver only means an
	// application edit waits out the cache TTL instead of invalidating on the spot.
	settings *settings.Resolver
}

// NewHandler constructs a Handler bound to service.
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
		cookies: authcookie.NewWriter(service.cfg, nil),
	}
}

// WithSettings points cookie construction and cache invalidation at the runtime
// settings resolver, and returns the handler for chaining.
//
// One resolver serves both: the refresh cookie this handler rotates is the same
// cookie /v1/client writes at sign-in, so both must read SameSite and lifetime
// from the same place; and every application write here must drop that
// application's cached settings so the change is visible on the next request
// rather than after the TTL.
func (h *Handler) WithSettings(r *settings.Resolver) *Handler {
	h.settings = r
	h.cookies = authcookie.NewWriter(h.service.cfg, r)
	return h
}

// RegisterRoutes mounts the OAuth2 and OIDC endpoints on app.
//
// pkMiddleware guards the authorization and token endpoints when supplied.
// adminMiddleware, when supplied, guards key rotation and the application
// management CRUD; without it those routes are mounted unguarded, which is only
// appropriate for a test harness.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware fiber.Handler, adminMiddleware ...fiber.Handler) {
	app.Get("/.well-known/openid-configuration", h.GetOIDCDiscovery)

	group := app.Group("/v1/oauth")
	group.Get("/jwks", h.GetJWKS)
	group.Get("/userinfo", h.GetUserInfo)
	if pkMiddleware != nil {
		group.Get("/authorize", pkMiddleware, h.Authorize)
		group.Post("/token", pkMiddleware, h.TokenExchange)
	} else {
		group.Get("/authorize", h.Authorize)
		group.Post("/token", h.TokenExchange)
	}

	registerAdmin := func(mw fiber.Handler) {
		var adminGroup, tenantAdminGroup fiber.Router
		if mw != nil {
			adminGroup = app.Group("/v1/admin", mw)
			tenantAdminGroup = app.Group("/v1/tenant", mw)
		} else {
			adminGroup = app.Group("/v1/admin")
			tenantAdminGroup = app.Group("/v1/tenant")
		}

		adminGroup.Post("/jwks/rotate", h.RotateJWKS)

		// Application management (§1.3). Every route is tenant-scoped by the
		// interceptor through the context adminMiddleware installs.
		apps := tenantAdminGroup.Group("/applications")
		apps.Post("/", h.CreateApplication)
		apps.Get("/", h.ListApplications)
		apps.Get("/:id", h.GetApplication)
		apps.Patch("/:id", h.UpdateApplication)
		apps.Delete("/:id", h.DeleteApplication)
	}

	if len(adminMiddleware) > 0 && adminMiddleware[0] != nil {
		registerAdmin(adminMiddleware[0])
	} else {
		registerAdmin(nil)
	}
}
