/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/impersonation/handler.go
 * Tier: HTTP Delivery Layer (Fiber Handlers)
 *
 * HTTP endpoints for admin user impersonation (FR-14): initiating a session,
 * exiting one, and reading or writing the tenant's impersonation policy.
 *
 * Step-up verification happens here rather than in the service, because it is a
 * property of the request — a password or second factor presented alongside it —
 * while the service's rules are properties of the tenant and the target.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package impersonation

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Impersonation-specific error codes. They are local to this package rather than
// part of the shared httperr set because they describe conditions no other
// endpoint can report, and they are published in docs/03-API-SPECIFICATION.md and
// docs/14-USER-IMPERSONATION.md — the string values are a wire contract, so
// renaming one is a breaking API change.
const (
	// codeUserIDRequired: the :user_id path parameter is empty.
	codeUserIDRequired httperr.Code = "user_id_required"
	// codeAdminPasswordRequired: password step-up was selected with no password.
	codeAdminPasswordRequired httperr.Code = "admin_password_required"
	// codeInvalidAdminPassword: the admin's step-up password did not verify.
	codeInvalidAdminPassword httperr.Code = "invalid_admin_password"
	// codeMFACodeRequired: TOTP step-up was selected with no code.
	codeMFACodeRequired httperr.Code = "mfa_code_required"
	// codeInvalidAdmin2FACode: the admin's step-up TOTP code did not verify.
	codeInvalidAdmin2FACode httperr.Code = "invalid_admin_2fa_code"
	// codeCredentialIDRequired: passkey step-up was selected with no credential.
	codeCredentialIDRequired httperr.Code = "credential_id_required"
	// codeAdminStepUpRequired: policy demands step-up and the request named no
	// recognised verification method.
	codeAdminStepUpRequired httperr.Code = "admin_step_up_required"
	// codeNotImpersonationSession: exit was called on an ordinary session.
	codeNotImpersonationSession httperr.Code = "not_an_impersonation_session"
	// codePolicyValidationFailed: the submitted impersonation policy is out of
	// bounds.
	codePolicyValidationFailed httperr.Code = "policy_validation_failed"
	// codeImpersonationDisabled: tenant policy has the feature switched off.
	codeImpersonationDisabled httperr.Code = "impersonation_disabled_by_policy"
	// codeTargetUserNotFound: no such user in the tenant.
	codeTargetUserNotFound httperr.Code = "target_user_not_found"
	// codeUserNotActive: the target account is suspended or not active.
	codeUserNotActive httperr.Code = "user_not_active"
	// codeCannotImpersonateSelf: caller and target are the same user.
	codeCannotImpersonateSelf httperr.Code = "cannot_impersonate_self"
	// codeHierarchyViolation: the target holds an administrative role and policy
	// restricts impersonating administrators.
	codeHierarchyViolation httperr.Code = "impersonation_hierarchy_violation"
	// codeUserOptInRequired: policy requires the target's support-access opt-in
	// and it is not set.
	codeUserOptInRequired httperr.Code = "user_opt_in_required"
	// codeValidationError: the request failed reason, ticket or duration
	// validation against the active policy.
	codeValidationError httperr.Code = "validation_error"
)

// PolicyRepository reads and writes a tenant's impersonation policy.
type PolicyRepository interface {
	// GetImpersonationPolicy returns the policy governing one of the tenant's
	// environments, or an error when it cannot be read.
	GetImpersonationPolicy(ctx context.Context, tenantID, environment string) (policy.ImpersonationPolicy, error)
	// UpdateImpersonationPolicy validates and persists the policy for one
	// environment, returning what was stored.
	UpdateImpersonationPolicy(ctx context.Context, tenantID, environment string, pol policy.ImpersonationPolicy) (policy.ImpersonationPolicy, error)
}

// StepUpVerifier re-checks an administrator's own credentials at the moment of
// an impersonation request.
type StepUpVerifier interface {
	// VerifyAdminPassword returns nil when the password is correct for userID.
	VerifyAdminPassword(ctx context.Context, userID string, password string) error
	// VerifyAdminTOTP returns nil when the code is valid for userID.
	VerifyAdminTOTP(ctx context.Context, userID string, code string) error
}

// Handler serves the impersonation endpoints.
type Handler struct {
	// svc applies the impersonation rules and issues tokens.
	svc *Service
	// policyRepo supplies the tenant policy; nil falls back to the defaults.
	policyRepo PolicyRepository
	// verifier performs step-up verification; nil skips it.
	verifier StepUpVerifier
	// blocklist records revoked token JTIs so middleware can reject replays
	// within the remaining lifetime of the original token.
	blocklist *tokenblocklist.Blocklist
}

// NewHandler returns an impersonation handler. A nil policyRepo makes every
// request fall back to policy.DefaultImpersonationPolicy. A nil blocklist
// leaves exit revocation server-side-only when Redis is unconfigured.
func NewHandler(svc *Service, policyRepo PolicyRepository, verifier StepUpVerifier, bl *tokenblocklist.Blocklist) *Handler {
	return &Handler{
		svc:        svc,
		policyRepo: policyRepo,
		verifier:   verifier,
		blocklist:  bl,
	}
}

// RegisterRoutes mounts the impersonation endpoints.
//
// adminMiddleware guards the admin and tenant groups. The client exit route
// requires BOTH pkMiddleware and clientAuthMiddleware: a publishable key
// identifies the application but establishes no user identity, so it cannot on
// its own gate a route that acts on the caller's session. Passing the
// publishable-key middleware in the clientAuthMiddleware slot leaves the route
// without the session guarantee the wiring appears to give it.
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware, clientAuthMiddleware, pkMiddleware fiber.Handler) {
	adminGroup := app.Group("/v1/admin")
	if adminMiddleware != nil {
		adminGroup.Use(adminMiddleware)
	}
	adminGroup.Post("/users/:user_id/impersonate", h.InitiateImpersonation)

	tenantGroup := app.Group("/v1/tenant")
	if adminMiddleware != nil {
		tenantGroup.Use(adminMiddleware)
	}
	tenantGroup.Get("/impersonation-policy", h.GetImpersonationPolicy)
	tenantGroup.Put("/impersonation-policy", h.UpdateImpersonationPolicy)

	clientGroup := app.Group("/v1/client")
	if pkMiddleware != nil {
		clientGroup.Use(pkMiddleware)
	}
	if clientAuthMiddleware != nil {
		clientGroup.Use(clientAuthMiddleware)
	}
	clientGroup.Post("/auth/impersonate/exit", h.ExitImpersonation)
}

// InitiateImpersonation handles POST /v1/admin/users/:user_id/impersonate.
//
// When policy requires step-up, the request must name a verification method and
// satisfy it before the service is consulted: "password" and "totp" are verified
// against the admin's own credentials, "webauthn"/"passkey" requires a credential
// ID whose assertion is checked in the payload, and anything else — including an
// absent method — is refused with codeAdminStepUpRequired.
//
// It answers 200 with the impersonation token, 400 for a missing user ID or
// unparseable body, 401 for a failed step-up, and otherwise whatever
// handleImpersonationError maps the service's error to. A policy that cannot be
// read falls back to the defaults rather than failing the request.
func (h *Handler) InitiateImpersonation(c *fiber.Ctx) error {
	tenantID, okTenant := requireTenantID(c)
	if !okTenant {
		return nil
	}
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
		p, err := h.policyRepo.GetImpersonationPolicy(c.UserContext(), tenantID, env)
		if err == nil {
			pol = p
		}
	}

	if pol.RequireStepUpAuth && h.verifier != nil && adminID != "" {
		method := strings.ToLower(strings.TrimSpace(req.VerificationMethod))
		switch method {
		case "password":
			if req.AdminPassword == "" {
				return httperr.BadRequest(c, codeAdminPasswordRequired,
					"admin_password is required for password step-up verification")
			}
			// Synthetic callers — a secret key, or the system actor — have no
			// password on record to verify against.
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
			if req.CredentialID == "" {
				return httperr.BadRequest(c, codeCredentialIDRequired,
					"credential_id is required for passkey step-up verification")
			}
		default:
			return httperr.BadRequest(c, codeAdminStepUpRequired,
				"admin step-up verification is required before initiating impersonation: specify verification_method ('password', 'totp', or 'passkey')")
		}
	}

	res, err := h.svc.ExecuteImpersonation(c.UserContext(), tenantID, env, adminID, targetUserID, req, pol)
	if err != nil {
		return handleImpersonationError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// ExitImpersonation handles POST /v1/client/auth/impersonate/exit, ending a
// support session by discarding the impersonation token client-side.
//
// It re-verifies the bearer token itself and answers 401 when it is missing or
// invalid, 400 when the session is not an impersonation session, and 200 with
// both identities so the client can restore the admin's own session.
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

	// Record the JTI so middleware rejects this token if the bearer replays it
	// before natural expiry. The TTL matches the token's remaining lifetime so
	// the blocklist key self-expires when the token would have anyway.
	remainingTTL := time.Until(time.Unix(claims.Exp, 0).UTC())
	h.blocklist.Block(c.UserContext(), claims.Jti, remainingTTL)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":         "impersonation session exited successfully",
		"impersonated_id": claims.Sub,
		"impersonator_id": claims.ImpersonatorID,
	})
}

// GetImpersonationPolicy handles GET /v1/tenant/impersonation-policy, answering
// 200 with the policy stored for the key's environment, or with the defaults when
// none is stored or it cannot be read.
func (h *Handler) GetImpersonationPolicy(c *fiber.Ctx) error {
	tenantID, okTenant := requireTenantID(c)
	if !okTenant {
		return nil
	}
	pol := policy.DefaultImpersonationPolicy()
	if h.policyRepo != nil {
		p, err := h.policyRepo.GetImpersonationPolicy(c.UserContext(), tenantID, getEnvironment(c))
		if err == nil {
			pol = p
		}
	}
	return c.Status(fiber.StatusOK).JSON(pol)
}

// UpdateImpersonationPolicy handles PUT /v1/tenant/impersonation-policy.
//
// The write lands in the environment the key names, so an impersonation rule can be
// loosened in test without touching the one that governs live administrators.
//
// It answers 200 with the stored policy, 400 for an unparseable body, 422 when
// the policy is out of bounds, and 500 when the write fails. With no repository
// configured it echoes the validated policy back without persisting it.
func (h *Handler) UpdateImpersonationPolicy(c *fiber.Ctx) error {
	tenantID, okTenant := requireTenantID(c)
	if !okTenant {
		return nil
	}
	var pol policy.ImpersonationPolicy
	if err := c.BodyParser(&pol); err != nil {
		return httperr.BadRequest(c, httperr.CodeInvalidRequestBody, "invalid request JSON body")
	}

	if err := policy.ValidateImpersonationPolicy(pol); err != nil {
		// The validator's message quotes the rejected email_notification_policy
		// value; the response states the rules instead of echoing the input.
		log.Printf("[error] %s %s impersonation.validate_policy: %v", c.Method(), c.Path(), err)
		return httperr.UnprocessableEntity(c, codePolicyValidationFailed,
			"impersonation policy rejected: max_duration_minutes must be between 1 and 60, and email_notification_policy must be IMMEDIATE, POST_SESSION, or DISABLED")
	}

	if h.policyRepo != nil {
		updated, err := h.policyRepo.UpdateImpersonationPolicy(c.UserContext(), tenantID, getEnvironment(c), pol)
		if err != nil {
			return httperr.SendInternal(c, "impersonation.update_policy", err)
		}
		return c.Status(fiber.StatusOK).JSON(updated)
	}

	return c.Status(fiber.StatusOK).JSON(pol)
}

// handleImpersonationError maps a service error onto its documented status and
// code. Unrecognised errors become a 422 with static prose: the default arm also
// catches the service's wrapped token-signing failure, whose text would
// otherwise carry JWT internals to the caller, so the detail stops at the log.
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
		log.Printf("[error] %s %s impersonation.execute: %v", c.Method(), c.Path(), err)
		return httperr.UnprocessableEntity(c, codeValidationError,
			"impersonation request rejected: verify reason (10-500 characters), ticket_id, and duration against the active tenant policy")
	}
}

// requireTenantID returns the tenant resolved by the admin guard, or answers 401
// and reports false. Callers must return nil when it reports false.
//
// Impersonation mints a token that acts as another user, so an unresolved tenant
// is refused rather than defaulted: substituting one would aim the most powerful
// operation on the admin surface at whichever tenant the fallback named.
func requireTenantID(c *fiber.Ctx) (string, bool) {
	return middleware.RequireTenantID(c)
}

// getEnvironment returns the environment resolved by the auth middleware,
// defaulting to "test" so an unresolved request cannot silently read or write
// live data.
func getEnvironment(c *fiber.Ctx) string {
	return middleware.GetEnvironment(c)
}

// getAdminID identifies the initiating admin from the request locals, preferring
// a console session, then an end-user session, then the API key that
// authenticated the call. It falls back to "usr_admin_system", which names no
// real account and has neither a password nor roles to verify against.
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

// extractBearerToken returns the Authorization: Bearer token, or "" when the
// header is absent or differently formed.
func extractBearerToken(c *fiber.Ctx) string {
	authHeader := c.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	return ""
}
