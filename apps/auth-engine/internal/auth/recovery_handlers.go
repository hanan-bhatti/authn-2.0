/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_handlers.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber HTTP handlers for Account Recovery flows (initiation, proofs, claim, cancellation).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// InitiateRecovery handles POST /v1/client/auth/recovery/initiate (Unauthenticated).
//
// The tenant and environment come from the publishable key that authenticated the
// request, never from the body. This endpoint looks the account up under a bypass
// context, so the tenant it is given is the only thing separating one customer's
// accounts from another's: honouring a body value would let any holder of a
// publishable key — which is public by design — start recovery against an account
// in a tenant they do not control.
func (h *Handler) InitiateRecovery(c *fiber.Ctx) error {
	var req struct {
		Email string `json:"email"`
	}

	if err := c.BodyParser(&req); err != nil || req.Email == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "email address is required")
	}

	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}
	env := middleware.GetEnvironment(c)

	deviceCookie := c.Cookies("authn_td_token")
	input := InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  env,
		Email:        req.Email,
		IPAddress:    c.IP(),
		UserAgent:    c.Get("User-Agent"),
		AcceptLang:   c.Get("Accept-Language"),
		DeviceCookie: deviceCookie,
	}

	res, err := h.recoveryService.InitiateRecovery(c.UserContext(), input)
	// Every branch below answers through the canonical envelope: the machine
	// code in `code` and the prose in `error`. Keeping the two in their own
	// fields is what lets the SDK branch on one identifier instead of
	// substring-matching across both.
	if errors.Is(err, ErrNoRecoveryMethodsAvailable) {
		return httperr.Send(c, fiber.StatusBadRequest, httperr.Code("no_recovery_methods_available"),
			"No account recovery methods are configured for this account. Please contact system support for administrative assistance.")
	}
	if errors.Is(err, ErrOriginBlacklisted) {
		return httperr.Send(c, fiber.StatusForbidden, httperr.Code("origin_blacklisted"),
			"origin IP, subnet, or device fingerprint is temporarily blacklisted following a security cancellation")
	}
	if err != nil {
		return httperr.SendInternal(c, "auth.recovery.initiate", err)
	}

	// H3: never expose the cancellation token to the party that initiated recovery.
	// The token is the owner's veto against an unwanted takeover; it must reach the
	// owner out-of-band (their alert email), not the caller of this endpoint — which
	// may be the attacker. The field stays on the struct (omitempty) for internal use
	// and the signed-link cancel flow; we blank it here so it is omitted from the body.
	res.CancellationToken = ""

	return c.Status(fiber.StatusOK).JSON(res)
}

// SubmitGuardianProof handles POST /v1/client/auth/recovery/proof/guardian.
func (h *Handler) SubmitGuardianProof(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string `json:"recovery_request_id"`
		SharePayload      string `json:"share_payload"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" || req.SharePayload == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id and share_payload are required")
	}

	thresholdReached, err := h.recoveryService.SubmitGuardianShareProof(c.UserContext(), req.RecoveryRequestID, req.SharePayload)
	if err != nil {
		// A repeat from a guardian already counted is a conflict, not a bad credential: the share
		// was right, it just cannot be spent twice.
		status := fiber.StatusBadRequest
		if errors.Is(err, ErrShareAlreadySubmitted) {
			status = fiber.StatusConflict
		}
		return sendServiceError(c, "auth.recovery.proof_guardian", status, err,
			httperr.CodeInvalidCredentials, ErrInvalidProof.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"threshold_reached": thresholdReached,
		"status":            map[bool]string{true: "proof_verified", false: "awaiting_more_shares"}[thresholdReached],
	})
}

// SubmitOldPasswordProof handles POST /v1/client/auth/recovery/proof/old-password.
func (h *Handler) SubmitOldPasswordProof(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string `json:"recovery_request_id"`
		Password          string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" || req.Password == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id and password are required")
	}

	if err := h.recoveryService.SubmitOldPasswordProof(c.UserContext(), req.RecoveryRequestID, req.Password); err != nil {
		return sendServiceError(c, "auth.recovery.proof_old_password", fiber.StatusBadRequest, err,
			httperr.CodeInvalidCredentials, ErrInvalidProof.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "proof_verified",
		"message": "Old password verified successfully",
	})
}

// SubmitSecurityQuestionsProof handles POST /v1/client/auth/recovery/proof/security-questions.
func (h *Handler) SubmitSecurityQuestionsProof(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string            `json:"recovery_request_id"`
		Answers           map[string]string `json:"answers"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id is required")
	}

	if err := h.recoveryService.SubmitSecurityQuestionsProof(c.UserContext(), req.RecoveryRequestID, req.Answers); err != nil {
		return sendServiceError(c, "auth.recovery.proof_security_questions", fiber.StatusBadRequest, err,
			httperr.CodeInvalidCredentials, ErrInvalidProof.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "proof_verified",
		"message": "Security questions verified successfully",
	})
}

// ClaimAccount handles POST /v1/client/auth/recovery/claim.
func (h *Handler) ClaimAccount(c *fiber.Ctx) error {
	var req ClaimAccountInput
	if err := c.BodyParser(&req); err != nil || req.RequestID == "" || req.ClaimToken == "" || req.NewPassword == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "request_id, claim_token, and new_password are required")
	}

	req.IPAddress = c.IP()
	req.UserAgent = c.Get("User-Agent")
	req.AcceptLang = c.Get("Accept-Language")

	res, err := h.recoveryService.ClaimAccount(c.UserContext(), req)
	if err != nil {
		return sendServiceError(c, "auth.recovery.claim", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, "invalid or expired account claim request")
	}

	if res.DeviceCookie != "" {
		h.cookies.SetTrustedDevice(c, getTenantID(c), middleware.GetEnvironment(c), res.DeviceCookie, trustedDeviceCookieTTL)
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// CancelRecoveryAuth handles POST /v1/client/auth/recovery/cancel (Authenticated Session).
func (h *Handler) CancelRecoveryAuth(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string `json:"recovery_request_id"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id is required")
	}

	// This is the one authenticated route in this file that verifies its own bearer token rather
	// than being registered with protected(). Cancellation must spare the session issuing it, so
	// the handler needs the session ID from the `sid` claim, and RequireClientAuth publishes only
	// the user, tenant and environment. Verifying here keeps that claim reachable.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: session token required")
	}
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.EncryptionKey)
	if err != nil {
		// The parse error names why the token failed (expired, bad signature, wrong algorithm),
		// which an unauthenticated caller must not learn.
		return httperr.Unauthorized(c, httperr.CodeSessionExpired, "unauthorized session: invalid or expired session token")
	}
	userID := claims.Sub
	sessionID := claims.SessionID
	privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, "", claims.Environment)

	if err := h.recoveryService.CancelRecoveryRequestByAuthenticatedSession(privacyCtx, userID, req.RecoveryRequestID, sessionID); err != nil {
		return sendServiceError(c, "auth.recovery.cancel_authenticated", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, ErrInvalidCancellationPoint.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "cancelled",
		"message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review.",
	})
}

// CancelRecoveryToken handles POST /v1/client/auth/recovery/cancel/token (Public Unauthenticated Signed Link).
func (h *Handler) CancelRecoveryToken(c *fiber.Ctx) error {
	var req struct {
		CancellationToken string `json:"cancellation_token"`
	}

	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.CancellationToken) == "" {
		// Fallback to query param token if body is empty
		req.CancellationToken = c.Query("cancellation_token")
	}

	if strings.TrimSpace(req.CancellationToken) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "cancellation_token is required")
	}

	if err := h.recoveryService.CancelRecoveryRequestBySignedToken(c.UserContext(), req.CancellationToken); err != nil {
		return sendServiceError(c, "auth.recovery.cancel_token", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, ErrInvalidCancellationPoint.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "cancelled",
		"message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review.",
	})
}
