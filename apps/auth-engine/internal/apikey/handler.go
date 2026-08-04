/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/handler.go
 * Tier: Internal Feature Package / Admin Key HTTP Handlers
 *
 * Description: Fiber HTTP handlers for Admin API Key CRUD management (create, list, revoke).
 *              Protected strictly by `RequireSecretKey` middleware.
 *              Enforces strict environment cross-isolation (test keys cannot manage live keys).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package apikey

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
)

// CreateKeyRequest defines the HTTP payload for issuing a new API key.
type CreateKeyRequest struct {
	Name          string `json:"name" example:"Production Stripe Webhook Key"`
	Type          string `json:"type" example:"publishable"` // "publishable" or "secret"
	Environment   string `json:"environment" example:"test"` // "test" or "live"
	ExpiresInDays *int   `json:"expires_in_days,omitempty"`
}

// KeyDTO represents public API key metadata returned in API responses (never includes key hash or secret string).
type KeyDTO struct {
	ID            string  `json:"id" example:"key_1a2b3c"`
	ApplicationID string  `json:"application_id" example:"app_test123"`
	Name          string  `json:"name" example:"Production Key"`
	Type          string  `json:"type" example:"publishable"`
	KeyPrefix     string  `json:"key_prefix" example:"pk_test_"`
	Environment   string  `json:"environment" example:"test"`
	CreatedAt     string  `json:"created_at" example:"2026-08-01T12:00:00Z"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
}

// CreateKeyResponse defines the response returned when issuing a new key (includes raw_key ONCE).
type CreateKeyResponse struct {
	Key    KeyDTO `json:"key"`
	RawKey string `json:"raw_key" example:"pk_test_12345678901234567890123456789012"`
}

// Handler handles HTTP requests for API Key CRUD operations.
type Handler struct {
	service *Service
}

// NewHandler creates a new API Key HTTP Handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes registers admin key management routes gated by secret key middleware.
func (h *Handler) RegisterRoutes(app *fiber.App, secretKeyMiddleware fiber.Handler) {
	group := app.Group("/v1/admin/keys")
	if secretKeyMiddleware != nil {
		group.Use(secretKeyMiddleware)
	}
	group.Post("/", h.CreateKey)
	group.Get("/", h.ListKeys)
	group.Post("/:id/revoke", h.RevokeKey)
}

// CreateKey issues a new publishable or secret API key for the caller's Application.
func (h *Handler) CreateKey(c *fiber.Ctx) error {
	appID, okApp := c.Locals("application_id").(string)
	callerEnv, okEnv := c.Locals("environment").(string)
	if !okApp || appID == "" || !okEnv || callerEnv == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: application context missing"})
	}

	var req CreateKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	keyType := KeyType(strings.ToLower(strings.TrimSpace(req.Type)))
	if keyType != TypePublishable && keyType != TypeSecret {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid key type: expected 'publishable' or 'secret'"})
	}

	reqEnv := strings.ToLower(strings.TrimSpace(req.Environment))
	if reqEnv == "" {
		reqEnv = callerEnv
	}

	// Environment isolation enforcement: caller's key environment mode must match the requested key environment
	if reqEnv != callerEnv {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "environment mismatch: test-mode admin key cannot manage live-mode keys and vice versa",
		})
	}

	var expiresAt *time.Time
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		exp := time.Now().AddDate(0, 0, *req.ExpiresInDays)
		expiresAt = &exp
	}

	gen, err := h.service.CreateKey(c.UserContext(), "", appID, req.Name, keyType, reqEnv, expiresAt)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	dto := KeyDTO{
		ID:            gen.ID,
		ApplicationID: appID,
		Name:          req.Name,
		Type:          string(gen.Type),
		KeyPrefix:     gen.Prefix,
		Environment:   reqEnv,
		CreatedAt:     time.Now().Format(time.RFC3339),
	}
	if expiresAt != nil {
		expStr := expiresAt.Format(time.RFC3339)
		dto.ExpiresAt = &expStr
	}

	return c.Status(fiber.StatusCreated).JSON(CreateKeyResponse{
		Key:    dto,
		RawKey: gen.RawKey,
	})
}

// ListKeys retrieves all API keys for the caller's Application.
func (h *Handler) ListKeys(c *fiber.Ctx) error {
	appID, okApp := c.Locals("application_id").(string)
	if !okApp || appID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: application context missing"})
	}

	keys, err := h.service.ListKeys(c.UserContext(), appID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	dtos := make([]KeyDTO, 0, len(keys))
	for _, k := range keys {
		dtos = append(dtos, toKeyDTO(k))
	}

	return c.Status(fiber.StatusOK).JSON(dtos)
}

// RevokeKey soft-revokes an API key by ID.
func (h *Handler) RevokeKey(c *fiber.Ctx) error {
	keyID := c.Params("id")
	if keyID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "key id is required"})
	}

	if err := h.service.RevokeKey(c.UserContext(), keyID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "revoked", "id": keyID})
}

func toKeyDTO(k *ent.ApiKey) KeyDTO {
	dto := KeyDTO{
		ID:            k.ID,
		ApplicationID: k.ApplicationID,
		Name:          k.Name,
		Type:          string(k.Type),
		KeyPrefix:     k.KeyPrefix,
		Environment:   string(k.Environment),
		CreatedAt:     k.CreatedAt.Format(time.RFC3339),
	}
	if k.ExpiresAt != nil {
		expStr := k.ExpiresAt.Format(time.RFC3339)
		dto.ExpiresAt = &expStr
	}
	if k.RevokedAt != nil {
		revStr := k.RevokedAt.Format(time.RFC3339)
		dto.RevokedAt = &revStr
	}
	return dto
}
