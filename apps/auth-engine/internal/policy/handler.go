/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/handler.go
 * Tier: Internal Feature Package / Policy Handler
 *
 * Admin HTTP endpoints for reading and configuring a tenant's password,
 * security, recovery and session policies.
 *
 * Every route is admin-only: these settings decide how strong a password must
 * be, whether verification is enforced, how long a session lasts, and how an
 * account can be recovered, so they carry the same guard as key management.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"context"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
)

// SettingsInvalidator drops cached policy for a tenant.
//
// It is an interface because the settings cache depends on this package, so the
// dependency cannot run the other way. settings.Resolver satisfies it.
type SettingsInvalidator interface {
	// InvalidateTenantPolicy evicts tenantID's cached session policy. It does not
	// report failure: an eviction that does not land costs one TTL of staleness,
	// which is not a reason to fail a write that already succeeded.
	InvalidateTenantPolicy(ctx context.Context, tenantID string)
}

// Handler serves the tenant policy endpoints.
type Handler struct {
	// repo reads and writes policies on the tenant record.
	repo *Repository
	// invalidator evicts cached policy after a write. Nil is valid and means
	// readers observe a change once the cache TTL elapses.
	invalidator SettingsInvalidator
}

// NewHandler returns a policy handler backed by repo.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// WithSettingsInvalidator attaches the cache whose entries policy writes evict,
// and returns the handler for chaining.
func (h *Handler) WithSettingsInvalidator(inv SettingsInvalidator) *Handler {
	h.invalidator = inv
	return h
}

// tenantOf returns the authenticated caller's tenant.
//
// The tenant is taken from the credential the admin guard verified, never from
// the request, so a caller holding a valid key for one tenant cannot address
// another by naming it.
func tenantOf(c *fiber.Ctx) (string, error) {
	return middleware.RequireTenantID(c)
}

// invalidate evicts tenantID's cached policy when a cache is attached.
func (h *Handler) invalidate(c *fiber.Ctx, tenantID string) {
	if h.invalidator != nil {
		h.invalidator.InvalidateTenantPolicy(c.UserContext(), tenantID)
	}
}

// GetPolicy handles GET /v1/tenant/password-policy, answering 200 with the
// tenant's password policy or 500 when it cannot be read.
func (h *Handler) GetPolicy(c *fiber.Ctx) error {
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}
	p, err := h.repo.GetPasswordPolicy(c.UserContext(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_password_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(p)
}

// UpdatePolicy handles PUT /v1/tenant/password-policy, answering 200 with the
// stored policy, 400 for an unparseable body, and 500 when the write fails.
// Out-of-range lengths are clamped by the repository rather than rejected.
func (h *Handler) UpdatePolicy(c *fiber.Ctx) error {
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}

	var req PasswordPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdatePasswordPolicy(c.UserContext(), tenantID, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_password_policy", err)
	}

	h.invalidate(c, tenantID)
	return c.Status(fiber.StatusOK).JSON(updated)
}

// GetSecurityPolicy handles GET /v1/tenant/security-policy, answering 200 with
// the tenant's security policy or 500 when it cannot be read.
func (h *Handler) GetSecurityPolicy(c *fiber.Ctx) error {
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}
	sp, err := h.repo.GetSecurityPolicy(c.UserContext(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_security_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(sp)
}

// UpdateSecurityPolicy handles PUT /v1/tenant/security-policy, answering 200
// with the stored policy, 400 for an unparseable body, and 500 when the write
// fails. Unrecognised enum values fall back to their defaults.
func (h *Handler) UpdateSecurityPolicy(c *fiber.Ctx) error {
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}

	var req SecurityPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateSecurityPolicy(c.UserContext(), tenantID, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_security_policy", err)
	}

	h.invalidate(c, tenantID)
	return c.Status(fiber.StatusOK).JSON(updated)
}

// GetRecoveryPolicy handles GET /v1/tenant/recovery-policy, answering 200 with
// the tenant's recovery policy or 500 when it cannot be read.
func (h *Handler) GetRecoveryPolicy(c *fiber.Ctx) error {
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}
	rp, err := h.repo.GetRecoveryPolicy(c.UserContext(), tenantID)
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
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}

	var req RecoveryPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateRecoveryPolicy(c.UserContext(), tenantID, req)
	if err != nil {
		log.Printf("[error] %s %s policy.update_recovery_policy: %v", c.Method(), c.Path(), err)
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"recovery policy rejected: review freeze window, claim token TTL, lockout schedule, and method toggles against the documented limits")
	}

	h.invalidate(c, tenantID)
	return c.Status(fiber.StatusOK).JSON(updated)
}

// GetSessionPolicy handles GET /v1/tenant/session-policy, answering 200 with the
// tenant's session policy or 500 when it cannot be read.
func (h *Handler) GetSessionPolicy(c *fiber.Ctx) error {
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}
	sp, err := h.repo.GetSessionPolicy(c.UserContext(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_session_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(sp)
}

// UpdateSessionPolicy handles PUT /v1/tenant/session-policy, answering 200 with
// the stored policy, 400 for an unparseable body, and 500 when the write fails.
//
// The repository normalizes token lifetimes and the SameSite value, so an
// out-of-range lifetime is clamped to the supported window rather than rejected.
// The response carries what was stored, which is what the caller should read
// back rather than assuming the request was applied verbatim.
func (h *Handler) UpdateSessionPolicy(c *fiber.Ctx) error {
	tenantID, err := tenantOf(c)
	if err != nil {
		return err
	}

	var req SessionPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateSessionPolicy(c.UserContext(), tenantID, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_session_policy", err)
	}

	h.invalidate(c, tenantID)
	return c.Status(fiber.StatusOK).JSON(updated)
}

// RegisterRoutes mounts the policy endpoints behind skMiddleware, the secret-key
// admin guard. All eight are admin operations and share one guard, so no policy
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

	sessionGroup := app.Group("/v1/tenant/session-policy")
	sessionGroup.Get("", mw, h.GetSessionPolicy)
	sessionGroup.Put("", mw, h.UpdateSessionPolicy)
}
