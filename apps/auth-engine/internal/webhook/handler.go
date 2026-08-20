/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/handler.go
 * Tier: HTTP REST Route Handler Layer
 *
 * Description: Fiber REST API routes for webhook endpoint management and delivery logs.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package webhook

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes mounts the webhook management endpoints on app behind
// adminMiddleware.
//
// An endpoint states which environment's events it receives, but a write can
// name live — or "all" — whichever key made it, so a test key that could
// register endpoints would still be able to point live traffic at a destination
// of its choosing. Every route that changes the list, or that makes it emit an
// HTTP request, therefore sits behind middleware.RequireLiveKey. Listing and
// reading stay open to either key, so a console signed in against test can still
// show a tenant what is configured.
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware fiber.Handler) {
	admin := app.Group("/v1/admin/webhooks", adminMiddleware)

	// Endpoint Management
	admin.Post("/endpoints", middleware.RequireLiveKey, h.CreateEndpoint)
	admin.Get("/endpoints", h.ListEndpoints)
	admin.Get("/endpoints/:id", h.GetEndpoint)
	admin.Put("/endpoints/:id", middleware.RequireLiveKey, h.UpdateEndpoint)
	admin.Delete("/endpoints/:id", middleware.RequireLiveKey, h.DeleteEndpoint)
	admin.Post("/endpoints/:id/ping", middleware.RequireLiveKey, h.SendTestPing)
	admin.Post("/endpoints/:id/rotate-secret", middleware.RequireLiveKey, h.RotateSecret)

	// Delivery History Logs
	admin.Get("/deliveries", h.ListDeliveries)
	admin.Post("/deliveries/:id/redeliver", middleware.RequireLiveKey, h.Redeliver)
}

func (h *Handler) CreateEndpoint(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)

	var req CreateEndpointRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.svc.CreateEndpoint(c.UserContext(), tenantID, req)
	if err != nil {
		if isValidationError(err) {
			return sendValidationError(c, err)
		}
		return httperr.SendInternal(c, "webhook.create_endpoint", err)
	}

	return c.Status(http.StatusCreated).JSON(resp)
}

func (h *Handler) ListEndpoints(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)

	endpoints, err := h.svc.ListEndpoints(c.UserContext(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "webhook.list_endpoints", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"endpoints": endpoints,
	})
}

func (h *Handler) GetEndpoint(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)
	endpointID := c.Params("id")

	ep, err := h.svc.GetEndpoint(c.UserContext(), tenantID, endpointID)
	if err != nil {
		if errors.Is(err, ErrEndpointNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "webhook endpoint not found")
		}
		return httperr.SendInternal(c, "webhook.get_endpoint", err)
	}

	return c.Status(http.StatusOK).JSON(ep)
}

func (h *Handler) UpdateEndpoint(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)
	endpointID := c.Params("id")

	var req UpdateEndpointRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.svc.UpdateEndpoint(c.UserContext(), tenantID, endpointID, req)
	if err != nil {
		if errors.Is(err, ErrEndpointNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "webhook endpoint not found")
		}
		if isValidationError(err) {
			return sendValidationError(c, err)
		}
		return httperr.SendInternal(c, "webhook.update_endpoint", err)
	}

	return c.Status(http.StatusOK).JSON(resp)
}

func (h *Handler) RotateSecret(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)
	endpointID := c.Params("id")

	resp, err := h.svc.RotateSecret(c.UserContext(), tenantID, endpointID)
	if err != nil {
		if errors.Is(err, ErrEndpointNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "webhook endpoint not found")
		}
		return httperr.SendInternal(c, "webhook.rotate_secret", err)
	}

	return c.Status(http.StatusOK).JSON(resp)
}

func (h *Handler) DeleteEndpoint(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)
	endpointID := c.Params("id")

	err := h.svc.DeleteEndpoint(c.UserContext(), tenantID, endpointID)
	if err != nil {
		if errors.Is(err, ErrEndpointNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "webhook endpoint not found")
		}
		return httperr.SendInternal(c, "webhook.delete_endpoint", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message":     "webhook endpoint deleted successfully",
		"endpoint_id": endpointID,
	})
}

func (h *Handler) SendTestPing(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)
	endpointID := c.Params("id")

	delivery, err := h.svc.SendTestPing(c.UserContext(), tenantID, endpointID, middleware.GetEnvironment(c))
	if err != nil {
		if errors.Is(err, ErrEndpointNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "webhook endpoint not found")
		}
		return httperr.SendInternal(c, "webhook.send_test_ping", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message":  "test ping webhook event delivered",
		"delivery": delivery,
	})
}

func (h *Handler) ListDeliveries(c *fiber.Ctx) error {
	endpointID := c.Query("endpoint_id")
	eventType := c.Query("event_type")
	limitStr := c.Query("limit", "50")

	limit, _ := strconv.Atoi(limitStr)

	deliveries, err := h.svc.ListDeliveries(c.UserContext(), endpointID, eventType, limit)
	if err != nil {
		return httperr.SendInternal(c, "webhook.list_deliveries", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"deliveries": deliveries,
	})
}

func (h *Handler) Redeliver(c *fiber.Ctx) error {
	tenantID := middleware.GetTenantID(c)
	deliveryID := c.Params("id")

	delivery, err := h.svc.Redeliver(c.UserContext(), tenantID, deliveryID)
	if err != nil {
		if errors.Is(err, ErrDeliveryNotFound) || errors.Is(err, ErrEndpointNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "delivery record or endpoint not found")
		}
		return httperr.SendInternal(c, "webhook.redeliver", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message":  "webhook re-delivery executed",
		"delivery": delivery,
	})
}

// validationSentinels are the failures that mean the caller sent something
// unusable, as opposed to something going wrong while serving a usable request.
//
// Listed once rather than per handler so that create and update cannot drift
// over which failures are the caller's fault — a sentinel missing from one of
// them would surface a validation failure as a 500.
var validationSentinels = []error{
	ErrInvalidURL,
	ErrEnvironmentRequired,
	ErrInvalidEnvironment,
	ErrInvalidEvents,
	ErrUnsupportedEvent,
}

// isValidationError reports whether err is one of validationSentinels, however
// deeply the service wrapped it.
func isValidationError(err error) bool {
	for _, sentinel := range validationSentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// sendValidationError maps the endpoint-validation sentinels onto static,
// client-safe prose. The sentinel text is deliberately not echoed back
// verbatim: the service may wrap these sentinels, and a wrapped error would
// otherwise carry internal detail into the response body.
func sendValidationError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrInvalidURL):
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			"invalid webhook URL: must be a valid HTTPS URL or localhost for development")
	case errors.Is(err, ErrEnvironmentRequired):
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			`environment is required: must be one of "test", "live" or "all"`)
	case errors.Is(err, ErrInvalidEnvironment):
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			`invalid environment: must be one of "test", "live" or "all"`)
	case errors.Is(err, ErrInvalidEvents):
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			"invalid events: at least one valid subscribed event type is required")
	default:
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			"unsupported event type provided")
	}
}
