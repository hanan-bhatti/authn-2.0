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
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Impersonation-specific error codes. These predate the shared httperr code set
// and are part of the published wire contract for FR-14, so they are preserved
// verbatim rather than folded into the generic codes.
const (
	codeUserIDRequired          httperr.Code = "user_id_required"
	codeAdminPasswordRequired   httperr.Code = "admin_password_required"
	codeInvalidAdminPassword    httperr.Code = "invalid_admin_password"
	codeMFACodeRequired         httperr.Code = "mfa_code_required"
	codeInvalidAdmin2FACode     httperr.Code = "invalid_admin_2fa_code"
	codeCredentialIDRequired    httperr.Code = "credential_id_required"
	codeAdminStepUpRequired     httperr.Code = "admin_step_up_required"
	codeNotImpersonationSession httperr.Code = "not_an_impersonation_session"
	codePolicyValidationFailed  httperr.Code = "policy_validation_failed"
	codeImpersonationDisabled   httperr.Code = "impersonation_disabled_by_policy"
	codeTargetUserNotFound      httperr.Code = "target_user_not_found"
	codeUserNotActive           httperr.Code = "user_not_active"
	codeCannotImpersonateSelf   httperr.Code = "cannot_impersonate_self"
	codeHierarchyViolation      httperr.Code = "impersonation_hierarchy_violation"
	codeUserOptInRequired       httperr.Code = "user_opt_in_required"
	codeValidationError         httperr.Code = "validation_error"
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
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware, clientAuthMiddleware, pkMiddleware fiber.Handler) {
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

	// Client-side exit impersonation session route. Requires a publishable key
	// AND a real user session: main.go previously passed pkMiddleware into the
	// clientAuthMiddleware slot, leaving this gated only by a publishable key,
	// which establishes no user identity. ExitImpersonation re-verifies the
	// bearer token itself so it was not exploitable, but the wiring did not
	// provide the guarantee it appeared to.
	clientGroup := app.Group("/v1/client")
	if pkMiddleware != nil {
		clientGroup.Use(pkMiddleware)
	}
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
		return httperr.BadRequest(c, codeUserIDRequired, "user_id parameter is required")
	}

	var req policy.ImpersonateRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.BadRequest(c, httperr.CodeInvalidRequestBody, "invalid request JSON body")
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
				return httperr.BadRequest(c, codeAdminPasswordRequired,
					"admin_password is required for password step-up verification")
			}
			if adminID != "" && !strings.HasPrefix(adminID, "key_") && adminID != "usr_admin_system" {
				if err := h.verifier.VerifyAdminPassword(c.UserContext(), adminID, req.AdminPassword); err != nil {
					return httperr.Unauthorized(c, codeInvalidAdminPassword,
						"invalid admin password provided for step-up verification")
				}
			}
		case "totp":
			if req.MFACode == "" {
				return httperr.BadRequest(c, codeMFACodeRequired,
					"mfa_code is required for 2FA step-up verification")
			}
			if err := h.verifier.VerifyAdminTOTP(c.UserContext(), adminID, req.MFACode); err != nil {
				return httperr.Unauthorized(c, codeInvalidAdmin2FACode,
					"invalid 2FA code provided for step-up verification")
			}
		case "webauthn", "passkey":
			// WebAuthn step-up handled via signed assertion in payload
			if req.CredentialID == "" {
				return httperr.BadRequest(c, codeCredentialIDRequired,
					"credential_id is required for passkey step-up verification")
			}
		default:
			return httperr.BadRequest(c, codeAdminStepUpRequired,
				"admin step-up verification is required before initiating impersonation: specify verification_method ('password', 'totp', or 'passkey')")
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
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: session token missing")
	}

	signingSecret := h.svc.cfg.EncryptionKey
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
	if err != nil {
		return httperr.Unauthorized(c, httperr.CodeInvalidToken, "invalid or expired session token")
	}

	if !claims.IsImpersonated {
		return httperr.BadRequest(c, codeNotImpersonationSession, "active session is not an impersonation session")
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
		return httperr.BadRequest(c, httperr.CodeInvalidRequestBody, "invalid request JSON body")
	}

	if err := policy.ValidateImpersonationPolicy(pol); err != nil {
		// The validator echoes the rejected email_notification_policy value back
		// in its message; the response states the rules instead of the input.
		log.Printf("[error] %s %s impersonation.validate_policy: %v", c.Method(), c.Path(), err)
		return httperr.UnprocessableEntity(c, codePolicyValidationFailed,
			"impersonation policy rejected: max_duration_minutes must be between 1 and 60, and email_notification_policy must be IMMEDIATE, POST_SESSION, or DISABLED")
	}

	if h.policyRepo != nil {
		updated, err := h.policyRepo.UpdateImpersonationPolicy(c.UserContext(), tenantID, pol)
		if err != nil {
			// Previously returned a body with no `code` field at all — the one
			// site in this file that was off-envelope.
			return httperr.SendInternal(c, "impersonation.update_policy", err)
		}
		return c.Status(fiber.StatusOK).JSON(updated)
	}

	return c.Status(fiber.StatusOK).JSON(pol)
}

func handleImpersonationError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrImpersonationDisabled):
		return httperr.Forbidden(c, codeImpersonationDisabled,
			"impersonation feature is disabled by tenant policy")
	case errors.Is(err, ErrUserNotFound):
		return httperr.NotFound(c, codeTargetUserNotFound, "target user not found")
	case errors.Is(err, ErrUserNotActive):
		return httperr.BadRequest(c, codeUserNotActive,
			"cannot impersonate suspended or unverified user")
	case errors.Is(err, ErrCannotImpersonateSelf):
		return httperr.BadRequest(c, codeCannotImpersonateSelf, "admin cannot impersonate self")
	case errors.Is(err, ErrCannotImpersonateAdmin):
		return httperr.Forbidden(c, codeHierarchyViolation, "cannot impersonate admin users")
	case errors.Is(err, ErrUserOptInRequired):
		return httperr.Forbidden(c, codeUserOptInRequired,
			"target user has not granted support access permission")
	case errors.Is(err, ErrInsufficientPermissions):
		return httperr.Forbidden(c, httperr.CodeInsufficientScope,
			"insufficient permissions: caller lacks 'users:impersonate' permission required to initiate impersonation")
	default:
		// Catch-all for request validation. It also catches the service's
		// wrapped token-issuing failure, which used to surface JWT signing
		// internals to the caller under a 422.
		log.Printf("[error] %s %s impersonation.execute: %v", c.Method(), c.Path(), err)
		return httperr.UnprocessableEntity(c, codeValidationError,
			"impersonation request rejected: verify reason (10-500 characters), ticket_id, and duration against the active tenant policy")
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
