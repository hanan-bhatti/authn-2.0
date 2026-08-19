/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/mfa_handlers.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber HTTP handlers for Multi-Factor Authentication (TOTP, SMS OTP, Backup Recovery Codes).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/accountstatus"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// TOTPConfirmRequest payload for confirming TOTP enrollment.
type TOTPConfirmRequest struct {
	Code string `json:"code" example:"123456"`
}

// TOTPVerifyRequest payload for verifying a TOTP code during session or login.
type TOTPVerifyRequest struct {
	Code     string `json:"code" example:"123456"`
	MFAToken string `json:"mfa_token,omitempty"`
	Method   string `json:"method,omitempty"`
}

// TOTPDisableRequest payload for removing TOTP 2FA.
type TOTPDisableRequest struct {
	Password string `json:"password" example:"SuperSecret123!"`
}

// RecoveryCodesRegenerateRequest payload for regenerating backup recovery codes.
type RecoveryCodesRegenerateRequest struct {
	Password string `json:"password" example:"SuperSecret123!"`
}

// SMSEnrollRequest payload for initiating SMS 2FA.
type SMSEnrollRequest struct {
	PhoneNumber string `json:"phone_number" example:"+12025550199"`
}

// SMSConfirmRequest payload for confirming SMS 2FA enrollment.
type SMSConfirmRequest struct {
	Code string `json:"code" example:"482910"`
}

// SMSDisableRequest payload for removing SMS 2FA.
type SMSDisableRequest struct {
	Password string `json:"password" example:"SuperSecret123!"`
}

// EnrollTOTP handles POST /v1/client/auth/2fa/totp/enroll.
// Generates a new TOTP secret for the authenticated user and stores it in pending state (is_enabled = false).
func (h *Handler) EnrollTOTP(c *fiber.Ctx) error {
	userID := getUserID(c)

	result, err := h.service.EnrollTOTP(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.totp.enroll", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"secret": result.Secret,
		"uri":    result.URI,
	})
}

// ConfirmTOTP handles POST /v1/client/auth/2fa/totp/confirm.
// Validates a 6-digit TOTP code against the pending secret and enables 2FA (is_enabled = true).
func (h *Handler) ConfirmTOTP(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req TOTPConfirmRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "code is required")
	}

	res, err := h.service.ConfirmTOTP(c.UserContext(), userID, strings.TrimSpace(req.Code))
	if err != nil {
		return sendServiceError(c, "auth.totp.confirm", fiber.StatusBadRequest, err,
			httperr.CodeInvalidMFACode, "unable to confirm TOTP enrollment with the supplied code")
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// VerifyTOTP handles POST /v1/client/auth/2fa/totp/verify and POST /v1/client/auth/2fa/verify.
// Validates a 6-digit TOTP code during login challenge or within an authenticated session.
func (h *Handler) VerifyTOTP(c *fiber.Ctx) error {
	var req TOTPVerifyRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "code is required")
	}

	mfaToken := req.MFAToken

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, msgInvalidClientType)
	}

	// 1. If MFA challenge token is provided (login 2FA verification flow)
	if mfaToken != "" {
		u, accessToken, refreshToken, err := h.service.VerifyTOTPChallenge(c.UserContext(), mfaToken, strings.TrimSpace(req.Code), req.Method, userAgent, ipAddress)
		if err != nil {
			if accountstatus.Refused(err) {
				return httperr.Send(c, fiber.StatusForbidden, httperr.CodeAccountDisabled, accountstatus.PublicMessage(err))
			}
			return sendServiceError(c, "auth.2fa.verify_challenge", fiber.StatusBadRequest, err,
				httperr.CodeInvalidMFACode, "two-factor verification failed")
		}

		var namePtr *string
		if u.Name != "" {
			namePtr = &u.Name
		}

		refreshTokenBody := ""
		if clientType == "native" || clientType == "mobile" {
			refreshTokenBody = refreshToken
		} else {
			h.cookies.SetRefreshToken(c, u.TenantID, string(u.Environment), refreshToken,
				h.cookies.RefreshTokenTTL(c.UserContext(), u.TenantID, string(u.Environment)))
		}

		return c.Status(fiber.StatusOK).JSON(AuthResponse{
			User: UserDTO{
				ID:            u.ID,
				Email:         u.Email,
				EmailVerified: u.EmailVerified,
				Name:          namePtr,
				Status:        string(u.Status),
				CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
			},
			AccessToken:  accessToken,
			RefreshToken: refreshTokenBody,
		})
	}

	// 2. Direct verification inside an already-authenticated session.
	//
	// This route is public because branch 1 above serves the login challenge, where the caller
	// holds an mfa_token and no session. The bearer path therefore has to authenticate itself.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: session token or two_factor_token required")
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.EncryptionKey)
	if err != nil {
		// The parse error names why the token failed (expired, bad signature, wrong algorithm),
		// which an unauthenticated caller must not learn.
		return httperr.Unauthorized(c, httperr.CodeSessionExpired, "unauthorized session: invalid or expired session token")
	}

	if err := h.service.Verify2FACode(c.UserContext(), claims.Sub, strings.TrimSpace(req.Code), req.Method); err != nil {
		return sendServiceError(c, "auth.2fa.verify", fiber.StatusBadRequest, err,
			httperr.CodeInvalidMFACode, "two-factor verification failed")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"valid": true,
	})
}

// DisableTOTP handles POST /v1/client/auth/2fa/totp/disable.
// Re-verifies current password using Argon2id, removes TOTP 2FA, and revokes all active user sessions for security.
func (h *Handler) DisableTOTP(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req TOTPDisableRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "password is required for 2FA step-up confirmation")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	if err := h.service.DisableTOTP(c.UserContext(), userID, req.Password, userAgent, ipAddress); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, "invalid password confirmation")
		}
		return sendServiceError(c, "auth.totp.disable", fiber.StatusBadRequest, err,
			httperr.CodeForbidden, "unable to disable TOTP 2FA")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "2FA TOTP disabled. All active sessions have been revoked for security.",
	})
}

// RegenerateRecoveryCodes handles POST /v1/client/auth/2fa/recovery-codes/regenerate.
// Requires Argon2id password step-up, invalidates all old recovery codes, and issues 16 fresh codes.
func (h *Handler) RegenerateRecoveryCodes(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req RecoveryCodesRegenerateRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "password is required for recovery codes regeneration step-up")
	}

	codes, err := h.service.RegenerateRecoveryCodes(c.UserContext(), userID, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, "invalid password confirmation")
		}
		return sendServiceError(c, "auth.recovery_codes.regenerate", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to regenerate recovery codes")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":        "recovery codes successfully regenerated",
		"recovery_codes": codes,
	})
}

// GetRecoveryCodesStatus handles GET /v1/client/auth/2fa/recovery-codes/status.
// Returns remaining unused count of recovery codes for the authenticated user without exposing code values.
func (h *Handler) GetRecoveryCodesStatus(c *fiber.Ctx) error {
	userID := getUserID(c)

	res, err := h.service.GetRecoveryCodesStatus(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.recovery_codes.status", err)
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// EnrollSMS handles POST /v1/client/auth/2fa/sms/enroll.
func (h *Handler) EnrollSMS(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req SMSEnrollRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.PhoneNumber) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "phone_number is required")
	}

	if err := h.service.BeginSMSEnrollment(c.UserContext(), userID, strings.TrimSpace(req.PhoneNumber)); err != nil {
		return sendServiceError(c, "auth.sms.enroll", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to begin SMS enrollment")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":            "OTP verification code sent via SMS",
		"expires_in_seconds": 300,
	})
}

// ConfirmSMS handles POST /v1/client/auth/2fa/sms/confirm.
func (h *Handler) ConfirmSMS(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req SMSConfirmRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "code is required")
	}

	res, err := h.service.ConfirmSMSEnrollment(c.UserContext(), userID, strings.TrimSpace(req.Code))
	if err != nil {
		return sendServiceError(c, "auth.sms.confirm", fiber.StatusBadRequest, err,
			httperr.CodeInvalidMFACode, "unable to confirm SMS enrollment with the supplied code")
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// DisableSMS handles DELETE /v1/client/auth/2fa/sms/disable.
func (h *Handler) DisableSMS(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req SMSDisableRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "password is required")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	if err := h.service.DisableSMS2FA(c.UserContext(), userID, req.Password, userAgent, ipAddress); err != nil {
		return sendServiceError(c, "auth.sms.disable", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to disable SMS 2FA")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "SMS 2FA disabled successfully",
	})
}
