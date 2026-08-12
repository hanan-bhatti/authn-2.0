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
)

const (
	// refreshTokenCookieName is the canonical cookie the engine writes rotated
	// refresh tokens to.
	refreshTokenCookieName = "authn_refresh_token"

	// metadataCacheControl is sent on the discovery and JWKS documents. Both are
	// public, change only on rotation, and are fetched by every relying party.
	metadataCacheControl = "public, max-age=3600"
)

// Handler exposes the OAuth2 and OIDC endpoints over HTTP.
type Handler struct {
	// service performs the underlying OAuth2 and OIDC operations.
	service *Service
}

// NewHandler constructs a Handler bound to service.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes mounts the OAuth2 and OIDC endpoints on app.
//
// pkMiddleware guards the authorization and token endpoints when supplied.
// adminMiddleware, when supplied, guards key rotation and application
// registration; without it those routes are mounted unguarded, which is only
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

	if len(adminMiddleware) > 0 && adminMiddleware[0] != nil {
		adminGroup := app.Group("/v1/admin", adminMiddleware[0])
		adminGroup.Post("/jwks/rotate", h.RotateJWKS)

		tenantAdminGroup := app.Group("/v1/tenant", adminMiddleware[0])
		tenantAdminGroup.Post("/applications", h.CreateApplication)
	} else {
		app.Post("/v1/admin/jwks/rotate", h.RotateJWKS)
		app.Post("/v1/tenant/applications", h.CreateApplication)
	}
}
