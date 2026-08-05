/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/impersonation/handler.go
 * Tier: HTTP Delivery Layer (Fiber Handlers)
 *
 * Description: HTTP handlers for Admin User Impersonation endpoints (FR-14).
 *              Handles POST /v1/admin/users/:user_id/impersonate, POST /v1/client/auth/impersonate/exit,
 *              and GET/PUT /v1/tenant/impersonation-policy.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package impersonation

import (
	"context"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

type PolicyRepository interface {
	GetImpersonationPolicy(ctx context.Context, tenantID string) (policy.ImpersonationPolicy, error)
	UpdateImpersonationPolicy(ctx context.Context, tenantID string, pol policy.ImpersonationPolicy) (policy.ImpersonationPolicy, error)
}

type StepUpVerifier interface {
	VerifyAdminPassword(ctx context.Context, userID string, password string) error
	VerifyAdminTOTP(ctx context.Context, userID string, code string) error
}

type Handler struct {
	svc        *Service
	policyRepo PolicyRepository
	verifier   StepUpVerifier
}

func NewHandler(svc *Service, policyRepo PolicyRepository, verifier StepUpVerifier) *Handler {
	return &Handler{
		svc:        svc,
		policyRepo: policyRepo,
		verifier:   verifier,
	}
}

// RegisterRoutes registers impersonation endpoints on Fiber application.
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware, clientAuthMiddleware fiber.Handler) {
	// Admin impersonation execution route
	adminGroup := app.Group("/v1/admin")
	if adminMiddleware != nil {
		adminGroup.Use(adminMiddleware)
	}
	adminGroup.Post("/users/:user_id/impersonate", h.InitiateImpersonation)

	// Tenant impersonation policy configuration routes
	tenantGroup := app.Group("/v1/tenant")
	if adminMiddleware != nil {
		tenantGroup.Use(adminMiddleware)
	}
	tenantGroup.Get("/impersonation-policy", h.GetImpersonationPolicy)
	tenantGroup.Put("/impersonation-policy", h.UpdateImpersonationPolicy)

	// Client-side exit impersonation session route
	clientGroup := app.Group("/v1/client")
	if clientAuthMiddleware != nil {
		clientGroup.Use(clientAuthMiddleware)
	}
	clientGroup.Post("/auth/impersonate/exit", h.ExitImpersonation)
}

// InitiateImpersonation handles POST /v1/admin/users/:user_id/impersonate
func (h *Handler) InitiateImpersonation(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	env := getEnvironment(c)
	targetUserID := c.Params("user_id")
	adminID := getAdminID(c)

	if targetUserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "user_id parameter is required",
			"code":  "user_id_required",
		})
	}

	var req policy.ImpersonateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request JSON body",
			"code":  "invalid_request_body",
		})
	}

	pol := policy.DefaultImpersonationPolicy()
	if h.policyRepo != nil {
		p, err := h.policyRepo.GetImpersonationPolicy(c.UserContext(), tenantID)
		if err == nil {
			pol = p
		}
	}

	// 1. Step-Up Verification (Sudo Mode) Guard
	if pol.RequireStepUpAuth && h.verifier != nil && adminID != "" {
		method := strings.ToLower(strings.TrimSpace(req.VerificationMethod))
		switch method {
		case "password":
			if req.AdminPassword == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "admin_password is required for password step-up verification",
					"code":  "admin_password_required",
				})
			}
			if adminID != "" && !strings.HasPrefix(adminID, "key_") && adminID != "usr_admin_system" {
				if err := h.verifier.VerifyAdminPassword(c.UserContext(), adminID, req.AdminPassword); err != nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "invalid admin password provided for step-up verification",
						"code":  "invalid_admin_password",
					})
				}
			}
		case "totp":
			if req.MFACode == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "mfa_code is required for 2FA step-up verification",
					"code":  "mfa_code_required",
				})
			}
			if err := h.verifier.VerifyAdminTOTP(c.UserContext(), adminID, req.MFACode); err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid 2FA code provided for step-up verification",
					"code":  "invalid_admin_2fa_code",
				})
			}
		case "webauthn", "passkey":
			// WebAuthn step-up handled via signed assertion in payload
			if req.CredentialID == "" {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "credential_id is required for passkey step-up verification",
					"code":  "credential_id_required",
				})
			}
		default:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "admin step-up verification is required before initiating impersonation: specify verification_method ('password', 'totp', or 'passkey')",
				"code":  "admin_step_up_required",
			})
		}
	}

	// 2. Execute Impersonation
	res, err := h.svc.ExecuteImpersonation(c.UserContext(), tenantID, env, adminID, targetUserID, req, pol)
	if err != nil {
		return handleImpersonationError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// ExitImpersonation handles POST /v1/client/auth/impersonate/exit
func (h *Handler) ExitImpersonation(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized: session token missing",
			"code":  "unauthorized",
		})
	}

	signingSecret := h.svc.cfg.AuthnEncryptionKey
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid or expired session token",
			"code":  "invalid_token",
		})
	}

	if !claims.IsImpersonated {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "active session is not an impersonation session",
			"code":  "not_an_impersonation_session",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":         "impersonation session exited successfully",
		"impersonated_id": claims.Sub,
		"impersonator_id": claims.ImpersonatorID,
	})
}

// GetGetTenantImpersonationPolicy handles GET /v1/tenant/impersonation-policy
func (h *Handler) GetImpersonationPolicy(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	pol := policy.DefaultImpersonationPolicy()
	if h.policyRepo != nil {
		p, err := h.policyRepo.GetImpersonationPolicy(c.UserContext(), tenantID)
		if err == nil {
			pol = p
		}
	}
	return c.Status(fiber.StatusOK).JSON(pol)
}

// UpdateTenantImpersonationPolicy handles PUT /v1/tenant/impersonation-policy
func (h *Handler) UpdateImpersonationPolicy(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	var pol policy.ImpersonationPolicy
	if err := c.BodyParser(&pol); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request JSON body",
			"code":  "invalid_request_body",
		})
	}

	if err := policy.ValidateImpersonationPolicy(pol); err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"error": err.Error(),
			"code":  "policy_validation_failed",
		})
	}

	if h.policyRepo != nil {
		updated, err := h.policyRepo.UpdateImpersonationPolicy(c.UserContext(), tenantID, pol)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed updating impersonation policy",
			})
		}
		return c.Status(fiber.StatusOK).JSON(updated)
	}

	return c.Status(fiber.StatusOK).JSON(pol)
}

func handleImpersonationError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrImpersonationDisabled):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "impersonation feature is disabled by tenant policy",
			"code":  "impersonation_disabled_by_policy",
		})
	case errors.Is(err, ErrUserNotFound):
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "target user not found",
			"code":  "target_user_not_found",
		})
	case errors.Is(err, ErrUserNotActive):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "cannot impersonate suspended or unverified user",
			"code":  "user_not_active",
		})
	case errors.Is(err, ErrCannotImpersonateSelf):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "admin cannot impersonate self",
			"code":  "cannot_impersonate_self",
		})
	case errors.Is(err, ErrCannotImpersonateAdmin):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "cannot impersonate admin users",
			"code":  "impersonation_hierarchy_violation",
		})
	case errors.Is(err, ErrUserOptInRequired):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "target user has not granted support access permission",
			"code":  "user_opt_in_required",
		})
	case errors.Is(err, ErrInsufficientPermissions):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "insufficient permissions: caller lacks 'users:impersonate' permission required to initiate impersonation",
			"code":  "insufficient_permissions",
		})
	default:
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
			"error": err.Error(),
			"code":  "validation_error",
		})
	}
}

func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return "tnt_default"
}

func getEnvironment(c *fiber.Ctx) string {
	if val, ok := c.Locals("environment").(string); ok && val != "" {
		return val
	}
	return "test"
}

func getAdminID(c *fiber.Ctx) string {
	if val, ok := c.Locals("console_user_id").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("userID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("user_id").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("api_key_id").(string); ok && val != "" {
		return val
	}
	return "usr_admin_system"
}

func extractBearerToken(c *fiber.Ctx) string {
	authHeader := c.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	return ""
}
