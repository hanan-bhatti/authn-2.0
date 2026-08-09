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
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// InitiateRecovery handles POST /v1/client/auth/recovery/initiate (Unauthenticated).
func (h *Handler) InitiateRecovery(c *fiber.Ctx) error {
	var req struct {
		TenantID    string `json:"tenant_id"`
		Environment string `json:"environment"`
		Email       string `json:"email"`
	}

	if err := c.BodyParser(&req); err != nil || req.Email == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "email address is required")
	}

	tenantID := req.TenantID
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_default"
		}
	}
	env := req.Environment
	if env == "" {
		env = "test"
	}

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

	res, err := h.recoveryService.InitiateRecovery(c.Context(), input)
	// These two branches previously returned an inverted envelope — the machine
	// code in `error` and the prose in `message` — which is what forced the SDK
	// to substring-match across both fields. The prose and the machine code keep
	// their existing values; only the fields they live in are swapped back.
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

	thresholdReached, err := h.recoveryService.SubmitGuardianShareProof(c.Context(), req.RecoveryRequestID, req.SharePayload)
	if err != nil {
		return sendServiceError(c, "auth.recovery.proof_guardian", fiber.StatusBadRequest, err,
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

	if err := h.recoveryService.SubmitOldPasswordProof(c.Context(), req.RecoveryRequestID, req.Password); err != nil {
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

	if err := h.recoveryService.SubmitSecurityQuestionsProof(c.Context(), req.RecoveryRequestID, req.Answers); err != nil {
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

	res, err := h.recoveryService.ClaimAccount(c.Context(), req)
	if err != nil {
		return sendServiceError(c, "auth.recovery.claim", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, "invalid or expired account claim request")
	}

	if res.DeviceCookie != "" {
		c.Cookie(&fiber.Cookie{
			Name:     "authn_td_token",
			Value:    res.DeviceCookie,
			Expires:  time.Now().Add(trustedDeviceCookieTTL),
			HTTPOnly: true,
			Secure:   h.service.config.CookieSecure(),
			SameSite: "Lax",
		})
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

	if err := h.recoveryService.CancelRecoveryRequestByAuthenticatedSession(c.Context(), userID, req.RecoveryRequestID, sessionID); err != nil {
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

	if err := h.recoveryService.CancelRecoveryRequestBySignedToken(c.Context(), req.CancellationToken); err != nil {
		return sendServiceError(c, "auth.recovery.cancel_token", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, ErrInvalidCancellationPoint.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "cancelled",
		"message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review.",
	})
}
