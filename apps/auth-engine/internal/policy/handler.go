/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/handler.go
 * Tier: Internal Feature Package / Policy Handler
 *
 * Description: HTTP handlers for inspecting and configuring tenant password policies.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"github.com/gofiber/fiber/v2"
)

// Handler handles HTTP requests for tenant password policy configuration.
type Handler struct {
	repo *Repository
}

// NewHandler constructs a new Policy Handler instance.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// GetPolicy retrieves the password policy for the specified tenant.
//
// @Summary Get Tenant Password Policy
// @Description Fetches the password policy options and enforcement settings for a tenant.
// @Tags Tenant Policy
// @Produce json
// @Param tenant_id query string false "Tenant ID (default: tnt_default)"
// @Success 200 {object} PasswordPolicy
// @Router /v1/tenant/password-policy [get]
func (h *Handler) GetPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	p, err := h.repo.GetPasswordPolicy(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(p)
}

// UpdatePolicy updates the password policy for the specified tenant.
//
// @Summary Update Tenant Password Policy
// @Description Updates password complexity options, enforcement mode, and length requirements for a tenant.
// @Tags Tenant Policy
// @Accept json
// @Produce json
// @Param tenant_id query string false "Tenant ID (default: tnt_default)"
// @Param policy body PasswordPolicy true "Updated Password Policy Payload"
// @Success 200 {object} PasswordPolicy
// @Failure 400 {object} map[string]interface{}
// @Router /v1/tenant/password-policy [put]
func (h *Handler) UpdatePolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")

	var req PasswordPolicy
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	updated, err := h.repo.UpdatePasswordPolicy(c.Context(), tenantID, req)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// GetSecurityPolicy retrieves the security policy for the specified tenant.
func (h *Handler) GetSecurityPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	sp, err := h.repo.GetSecurityPolicy(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(sp)
}

// UpdateSecurityPolicy updates the security policy for the specified tenant.
func (h *Handler) UpdateSecurityPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")

	var req SecurityPolicy
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	updated, err := h.repo.UpdateSecurityPolicy(c.Context(), tenantID, req)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// GetRecoveryPolicy retrieves the recovery policy for the specified tenant.
func (h *Handler) GetRecoveryPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	rp, err := h.repo.GetRecoveryPolicy(c.Context(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusOK).JSON(rp)
}

// UpdateRecoveryPolicy validates and updates the account recovery policy for the specified tenant.
func (h *Handler) UpdateRecoveryPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")

	var req RecoveryPolicy
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	updated, err := h.repo.UpdateRecoveryPolicy(c.Context(), tenantID, req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// RegisterRoutes registers tenant policy routes with Fiber router.
func (h *Handler) RegisterRoutes(app *fiber.App) {
	passwordGroup := app.Group("/v1/tenant/password-policy")
	passwordGroup.Get("", h.GetPolicy)
	passwordGroup.Put("", h.UpdatePolicy)

	securityGroup := app.Group("/v1/tenant/security-policy")
	securityGroup.Get("", h.GetSecurityPolicy)
	securityGroup.Put("", h.UpdateSecurityPolicy)

	recoveryGroup := app.Group("/v1/tenant/recovery-policy")
	recoveryGroup.Get("", h.GetRecoveryPolicy)
	recoveryGroup.Put("", h.UpdateRecoveryPolicy)
}
