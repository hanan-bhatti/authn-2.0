/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/webauthn_handlers.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber HTTP handlers for WebAuthn Passkeys (registration, assertion login, passkey management).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// WebAuthnRegisterFinishRequest payload for completing passkey registration.
type WebAuthnRegisterFinishRequest struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name,omitempty"`
}

// WebAuthnLoginBeginRequest payload for starting passkey login challenge flow.
type WebAuthnLoginBeginRequest struct {
	MFAToken string `json:"mfa_token"`
}

// WebAuthnLoginFinishRequest payload for completing passkey login challenge flow.
type WebAuthnLoginFinishRequest struct {
	MFAToken  string `json:"mfa_token"`
	SessionID string `json:"session_id"`
}

// PasskeyDeleteRequest payload for removing a passkey.
type PasskeyDeleteRequest struct {
	Password string `json:"password,omitempty"`
}

// BeginWebAuthnRegistration handles POST /v1/client/auth/2fa/webauthn/register/begin.
func (h *Handler) BeginWebAuthnRegistration(c *fiber.Ctx) error {
	userID := getUserID(c)

	options, sessionID, err := h.service.BeginWebAuthnRegistration(c.UserContext(), userID)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.register_begin", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to begin passkey registration")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"options":    options,
		"session_id": sessionID,
	})
}

// FinishWebAuthnRegistration handles POST /v1/client/auth/2fa/webauthn/register/finish.
func (h *Handler) FinishWebAuthnRegistration(c *fiber.Ctx) error {
	userID := getUserID(c)

	sessionID := c.Query("session_id")
	passkeyName := c.Query("name")
	if sessionID == "" {
		var req WebAuthnRegisterFinishRequest
		_ = c.BodyParser(&req)
		sessionID = req.SessionID
		if req.Name != "" {
			passkeyName = req.Name
		}
	}
	if sessionID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "session_id is required")
	}

	httpReq, err := http.NewRequestWithContext(c.UserContext(), c.Method(), c.OriginalURL(), bytes.NewReader(c.Body()))
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeInvalidRequestBody, "invalid http request format")
	}
	for k, v := range c.GetReqHeaders() {
		if len(v) > 0 {
			httpReq.Header.Set(k, v[0])
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := h.service.FinishWebAuthnRegistration(c.UserContext(), userID, sessionID, httpReq, passkeyName)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.register_finish", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to complete passkey registration")
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// BeginWebAuthnLogin handles POST /v1/client/auth/2fa/webauthn/login/begin.
func (h *Handler) BeginWebAuthnLogin(c *fiber.Ctx) error {
	var req WebAuthnLoginBeginRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.MFAToken) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "mfa_token is required")
	}

	options, sessionID, userID, err := h.service.BeginWebAuthnLogin(c.UserContext(), req.MFAToken)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.login_begin", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to begin passkey login")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"options":    options,
		"session_id": sessionID,
		"user_id":    userID,
	})
}

// FinishWebAuthnLogin handles POST /v1/client/auth/2fa/webauthn/login/finish.
func (h *Handler) FinishWebAuthnLogin(c *fiber.Ctx) error {
	mfaToken := c.Query("mfa_token")
	sessionID := c.Query("session_id")
	if mfaToken == "" || sessionID == "" {
		var req WebAuthnLoginFinishRequest
		_ = c.BodyParser(&req)
		if mfaToken == "" {
			mfaToken = req.MFAToken
		}
		if sessionID == "" {
			sessionID = req.SessionID
		}
	}
	if mfaToken == "" || sessionID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "mfa_token and session_id are required")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, msgInvalidClientType)
	}

	httpReq, err := http.NewRequestWithContext(c.UserContext(), c.Method(), c.OriginalURL(), bytes.NewReader(c.Body()))
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeInvalidRequestBody, "invalid http request format")
	}
	for k, v := range c.GetReqHeaders() {
		if len(v) > 0 {
			httpReq.Header.Set(k, v[0])
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	u, accessToken, refreshToken, err := h.service.FinishWebAuthnLogin(c.UserContext(), mfaToken, sessionID, httpReq, userAgent, ipAddress)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.login_finish", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to complete passkey login")
	}

	var namePtr *string
	if u.Name != "" {
		namePtr = &u.Name
	}

	refreshTokenBody := ""
	if clientType == "native" || clientType == "mobile" {
		refreshTokenBody = refreshToken
	} else {
		h.cookies.SetRefreshToken(c, u.TenantID, refreshToken,
			h.cookies.RefreshTokenTTL(c.UserContext(), u.TenantID))
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

// ListWebAuthnPasskeys handles GET /v1/client/auth/2fa/webauthn/credentials.
func (h *Handler) ListWebAuthnPasskeys(c *fiber.Ctx) error {
	userID := getUserID(c)

	credentials, err := h.service.ListWebAuthnPasskeys(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.webauthn.list_passkeys", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"credentials": credentials,
	})
}

// DeleteWebAuthnPasskey handles DELETE /v1/client/auth/2fa/webauthn/credentials/:id.
func (h *Handler) DeleteWebAuthnPasskey(c *fiber.Ctx) error {
	userID := getUserID(c)

	passkeyID := c.Params("id")
	if passkeyID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "passkey id is required")
	}

	var req PasskeyDeleteRequest
	_ = c.BodyParser(&req)

	if err := h.service.DeleteWebAuthnPasskey(c.UserContext(), userID, passkeyID, req.Password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, "invalid password step-up confirmation required to delete your last remaining 2FA method")
		}
		return sendServiceError(c, "auth.webauthn.delete_passkey", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to delete passkey")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "passkey successfully deleted",
	})
}
