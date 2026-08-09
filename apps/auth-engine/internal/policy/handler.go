/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/handler.go
 * Tier: Internal Feature Package / Policy Handler
 *
 * Admin HTTP endpoints for reading and configuring a tenant's password,
 * security and recovery policies.
 *
 * Every route is admin-only: these settings decide how strong a password must
 * be, whether verification is enforced, and how an account can be recovered, so
 * they carry the same guard as key management.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// Handler serves the tenant policy endpoints.
type Handler struct {
	// repo reads and writes policies on the tenant record.
	repo *Repository
}

// NewHandler returns a policy handler backed by repo.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// GetPolicy handles GET /v1/tenant/password-policy, answering 200 with the
// tenant's password policy or 500 when it cannot be read.
func (h *Handler) GetPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	p, err := h.repo.GetPasswordPolicy(c.Context(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_password_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(p)
}

// UpdatePolicy handles PUT /v1/tenant/password-policy, answering 200 with the
// stored policy, 400 for an unparseable body, and 500 when the write fails.
// Out-of-range lengths are clamped by the repository rather than rejected.
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

// GetSecurityPolicy handles GET /v1/tenant/security-policy, answering 200 with
// the tenant's security policy or 500 when it cannot be read.
func (h *Handler) GetSecurityPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	sp, err := h.repo.GetSecurityPolicy(c.Context(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_security_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(sp)
}

// UpdateSecurityPolicy handles PUT /v1/tenant/security-policy, answering 200
// with the stored policy, 400 for an unparseable body, and 500 when the write
// fails. Unrecognised enum values fall back to their defaults.
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

// GetRecoveryPolicy handles GET /v1/tenant/recovery-policy, answering 200 with
// the tenant's recovery policy or 500 when it cannot be read.
func (h *Handler) GetRecoveryPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")
	rp, err := h.repo.GetRecoveryPolicy(c.Context(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_recovery_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(rp)
}

// UpdateRecoveryPolicy handles PUT /v1/tenant/recovery-policy, answering 200
// with the stored policy, 400 for an unparseable body, and 400 when the policy
// is rejected.
//
// The repository reports both rule violations and write failures through one
// error, and the write failures carry ORM and SQL text, so the detail stops at
// the log and the caller receives a fixed message pointing at the documented
// limits.
func (h *Handler) UpdateRecoveryPolicy(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id", "tnt_default")

	var req RecoveryPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateRecoveryPolicy(c.Context(), tenantID, req)
	if err != nil {
		log.Printf("[error] %s %s policy.update_recovery_policy: %v", c.Method(), c.Path(), err)
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"recovery policy rejected: review freeze window, claim token TTL, lockout schedule, and method toggles against the documented limits")
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// RegisterRoutes mounts the policy endpoints behind skMiddleware, the secret-key
// admin guard. All six are admin operations and share one guard, so no policy
// route can be added on a weaker one by accident.
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
