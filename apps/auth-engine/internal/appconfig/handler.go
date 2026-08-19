/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/appconfig/handler.go
 * Tier: HTTP Delivery Layer (Fiber Handlers)
 *
 * The one request a sign-in page makes before it renders, and the administrative
 * routes that configure what it returns.
 *
 * The public route sits behind the publishable key alone: it must answer before
 * anyone has signed in, which is the whole point of it, so a session token is not
 * available to demand. What that key buys is scope, not trust — it resolves the
 * tenant, application and environment, so a caller cannot bootstrap a workspace
 * their key does not belong to, and cannot widen the answer by naming one.
 *
 * The branding routes are admin-only. Branding decides what a tenant's users see
 * at the moment they are asked for a password, so the ability to change it is the
 * ability to restyle a login page — the same guard as any other tenant setting.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package appconfig

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

// bootstrapCacheControl is the caching directive on the public document.
//
// "private" is load-bearing rather than conventional. The publishable key travels
// in a header, so every tenant's bootstrap document lives at the same URL; a
// shared cache keyed on the URL alone would serve one tenant's branding and
// sign-in options to the next caller. "private" confines the copy to the one
// browser that fetched it, and the Vary header below keeps even that browser from
// mixing two applications' answers.
//
// A minute is short enough that flipping a provider on is effectively immediate
// and long enough that a page reloaded during a sign-in attempt does not re-read
// the tenant row each time.
const bootstrapCacheControl = "private, max-age=60"

// bootstrapVary names the request headers the answer depends on, so a browser
// cache keyed on the URL cannot return the wrong tenant's document. The key
// decides the whole payload; Origin decides whether the request is answered at
// all, since the application's own origin allowlist is applied to it.
const bootstrapVary = "X-Authn-Publishable-Key, Origin"

// Handler serves the bootstrap document and the branding administration routes.
type Handler struct {
	// svc assembles the document and applies branding writes.
	svc *Service
}

// NewHandler returns a handler bound to svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// GetAppConfig handles GET /v1/client/app-config, answering 200 with the sign-in
// page's bootstrap document.
//
// It has no failure path beyond the guard. Every read behind it degrades to a
// documented default, because a page that cannot bootstrap cannot sign anyone in:
// the worst answer available is an unstyled page offering the engine's base
// credentials, which is still a usable one.
func (h *Handler) GetAppConfig(c *fiber.Ctx) error {
	tenantID, ok := middleware.RequireTenantID(c)
	if !ok {
		return nil
	}
	applicationID, _ := c.Locals("application_id").(string)
	environment := middleware.GetEnvironment(c)

	doc := h.svc.AppConfig(c.UserContext(), tenantID, applicationID, environment)

	c.Set(fiber.HeaderCacheControl, bootstrapCacheControl)
	c.Set(fiber.HeaderVary, bootstrapVary)
	return c.Status(fiber.StatusOK).JSON(doc)
}

// GetBranding handles GET /v1/tenant/branding, answering 200 with the branding
// stored for the key's environment or 500 when it cannot be read.
func (h *Handler) GetBranding(c *fiber.Ctx) error {
	tenantID, ok := middleware.RequireTenantID(c)
	if !ok {
		return nil
	}

	b, err := h.svc.Branding(c.UserContext(), tenantID, middleware.GetEnvironment(c))
	if err != nil {
		return httperr.SendInternal(c, "appconfig.get_branding", err)
	}
	return c.Status(fiber.StatusOK).JSON(b)
}

// UpdateBranding handles PUT /v1/tenant/branding, answering 200 with what was
// stored, 400 for an unparseable body or a rejected value, 404 for an
// unprovisioned tenant, and 500 when the write fails.
//
// The value is validated here rather than left to the service, so an
// administrator who mistypes a colour is told which field was refused. Every
// message ValidateBranding produces is authored in this package and names a field
// and the expected form, so returning it verbatim cannot leak storage detail. The
// service validates again as a safety net for any other caller it acquires.
//
// The write lands in the environment the key names, so restyling a test sign-in page
// leaves the live one alone until the change is published.
func (h *Handler) UpdateBranding(c *fiber.Ctx) error {
	tenantID, ok := middleware.RequireTenantID(c)
	if !ok {
		return nil
	}

	var req Branding
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	validated, err := ValidateBranding(req)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, err.Error())
	}

	stored, err := h.svc.UpdateBranding(c.UserContext(), tenantID, middleware.GetEnvironment(c), validated)
	switch {
	case errors.Is(err, policy.ErrTenantNotFound):
		return httperr.NotFound(c, httperr.CodeNotFound, "tenant not found")
	case err != nil:
		return httperr.SendInternal(c, "appconfig.update_branding", err)
	}

	return c.Status(fiber.StatusOK).JSON(stored)
}

// RegisterRoutes mounts the bootstrap document behind pkMiddleware and the
// branding administration behind adminMiddleware.
//
// The two guards are attached per route rather than to a group, so the public
// document and the administrative write cannot end up sharing whichever guard was
// applied to a common prefix. They have no prefix in common here, and keeping the
// guard on the route is what keeps that true if one is ever moved.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware, adminMiddleware fiber.Handler) {
	app.Get("/v1/client/app-config", pkMiddleware, h.GetAppConfig)

	app.Get("/v1/tenant/branding", adminMiddleware, h.GetBranding)
	app.Put("/v1/tenant/branding", adminMiddleware, h.UpdateBranding)
}
