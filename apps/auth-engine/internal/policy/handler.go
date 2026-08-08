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
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
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
		return httperr.SendInternal(c, "policy.get_password_policy", err)
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
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdatePasswordPolicy(c.Context(), tenantID, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_password_policy", err)
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// GetSecurityPolicy retrieves the security policy for the specified tenant.
func (h *Handler) GetSecurityPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	sp, err := h.repo.GetSecurityPolicy(c.Context(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_security_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(sp)
}

// UpdateSecurityPolicy updates the security policy for the specified tenant.
func (h *Handler) UpdateSecurityPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")

	var req SecurityPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateSecurityPolicy(c.Context(), tenantID, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_security_policy", err)
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// GetRecoveryPolicy retrieves the recovery policy for the specified tenant.
func (h *Handler) GetRecoveryPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	rp, err := h.repo.GetRecoveryPolicy(c.Context(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_recovery_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(rp)
}

// UpdateRecoveryPolicy validates and updates the account recovery policy for the specified tenant.
func (h *Handler) UpdateRecoveryPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")

	var req RecoveryPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateRecoveryPolicy(c.Context(), tenantID, req)
	if err != nil {
		// The repository returns both rule-validation failures and tenant-write
		// failures through this one path, and the write failures carry ent/SQL
		// text. The 400 is preserved; the detail now stops at the log.
		log.Printf("[error] %s %s policy.update_recovery_policy: %v", c.Method(), c.Path(), err)
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"recovery policy rejected: review freeze window, claim token TTL, lockout schedule, and method toggles against the documented limits")
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// RegisterRoutes registers tenant policy admin routes behind secret key authentication.
// All policy endpoints are admin-only operations — they require a valid sk_... secret key
// in the Authorization: Bearer header (same guard as /v1/admin/keys/*).
func (h *Handler) RegisterRoutes(app *fiber.App, skMiddleware fiber.Handler) {
	mw := skMiddleware

	passwordGroup := app.Group("/v1/tenant/password-policy")
	passwordGroup.Get("", mw, h.GetPolicy)
	passwordGroup.Put("", mw, h.UpdatePolicy)

	securityGroup := app.Group("/v1/tenant/security-policy")
	securityGroup.Get("", mw, h.GetSecurityPolicy)
	securityGroup.Put("", mw, h.UpdateSecurityPolicy)

	recoveryGroup := app.Group("/v1/tenant/recovery-policy")
	recoveryGroup.Get("", mw, h.GetRecoveryPolicy)
	recoveryGroup.Put("", mw, h.UpdateRecoveryPolicy)
}
