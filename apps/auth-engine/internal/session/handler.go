// Copyright (c) 2026 Hanan Bhatti
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package session

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Refresh-token failure codes that predate internal/httperr and are already part
// of the published wire contract (the SDK branches on them), but have no constant
// in httperr. They are spelled out here rather than renamed to an existing code,
// because renaming one is a breaking API change.
const (
	codeSessionCompromised httperr.Code = "session_compromised"
	codeSessionRevoked     httperr.Code = "session_revoked"
)

// msgSessionAuthRequired is the single 401 message used by every client session
// endpoint. It is deliberately identical across handlers so that a caller cannot
// distinguish "no token" from "token rejected".
const msgSessionAuthRequired = "session authentication required: missing or invalid access token"

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware, adminMiddleware fiber.Handler) {
	// Client endpoints (session authenticated or publishable key)
	client := app.Group("/v1/client/sessions", pkMiddleware)
	client.Get("/", h.ListSessions)
	client.Post("/revoke", h.RevokeSession)
	client.Post("/revoke-others", h.RevokeOtherSessions)
	client.Post("/revoke-all", h.RevokeAllSessions)

	// Token Refresh endpoint
	app.Post("/v1/client/auth/refresh", pkMiddleware, h.RefreshTokens)

	// Admin endpoints (secret key or console JWT)
	admin := app.Group("/v1/admin/users/:user_id/sessions", adminMiddleware)
	admin.Get("/", h.AdminListUserSessions)
	admin.Post("/revoke-all", h.AdminRevokeAllUserSessions)
}

func (h *Handler) getUserIDAndSessionID(c *fiber.Ctx) (string, string) {
	var userID string
	var sessionID string

	if val := c.Locals("user_id"); val != nil {
		userID = val.(string)
	} else if val := c.Locals("userID"); val != nil {
		userID = val.(string)
	} else if val := c.Locals("console_user_id"); val != nil {
		userID = val.(string)
	}

	if val := c.Locals("session_id"); val != nil {
		sessionID = val.(string)
	} else if val := c.Locals("sessionID"); val != nil {
		sessionID = val.(string)
	}

	// If userID or sessionID is missing, try parsing Authorization Bearer <jwt>
	if userID == "" || sessionID == "" {
		authHeader := c.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.svc.cfg.AuthnEncryptionKey)
			if err == nil && claims != nil {
				if userID == "" {
					userID = claims.Sub
				}
				if sessionID == "" {
					sessionID = claims.SessionID
				}
			}
		}
	}

	return userID, sessionID
}

func (h *Handler) ListSessions(c *fiber.Ctx) error {
	userID, currentSessionID := h.getUserIDAndSessionID(c)
	if userID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, msgSessionAuthRequired)
	}

	sessions, err := h.svc.ListUserSessions(c.UserContext(), userID, currentSessionID)
	if err != nil {
		return httperr.SendInternal(c, "session.list", err)
	}

	return c.JSON(fiber.Map{"sessions": sessions})
}

func (h *Handler) RevokeSession(c *fiber.Ctx) error {
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.SessionID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "session_id is required")
	}

	userID, _ := h.getUserIDAndSessionID(c)
	if userID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, msgSessionAuthRequired)
	}

	err := h.svc.RevokeSession(c.UserContext(), userID, req.SessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "session not found")
		}
		if errors.Is(err, ErrSessionNotOwned) {
			return httperr.Forbidden(c, httperr.CodeForbidden, ErrSessionNotOwned.Error())
		}
		return httperr.SendInternal(c, "session.revoke", err)
	}

	return c.JSON(fiber.Map{"message": "session revoked", "session_id": req.SessionID})
}

func (h *Handler) RevokeOtherSessions(c *fiber.Ctx) error {
	userID, currentSessionID := h.getUserIDAndSessionID(c)
	if userID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, msgSessionAuthRequired)
	}

	count, err := h.svc.RevokeOtherSessions(c.UserContext(), userID, currentSessionID)
	if err != nil {
		return httperr.SendInternal(c, "session.revoke_others", err)
	}

	return c.JSON(fiber.Map{"message": "all other sessions revoked", "count": count})
}

func (h *Handler) RevokeAllSessions(c *fiber.Ctx) error {
	userID, _ := h.getUserIDAndSessionID(c)
	if userID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, msgSessionAuthRequired)
	}

	count, err := h.svc.RevokeAllSessions(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "session.revoke_all", err)
	}

	return c.JSON(fiber.Map{"message": "all sessions revoked", "count": count})
}

func (h *Handler) RefreshTokens(c *fiber.Ctx) error {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = c.BodyParser(&req)

	rawToken := req.RefreshToken
	if rawToken == "" {
		rawToken = c.Cookies("authn_refresh_token")
	}
	if rawToken == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "refresh_token required")
	}

	tenantID := ""
	if val := c.Locals("tenant_id"); val != nil {
		tenantID = val.(string)
	} else if val := c.Locals("tenantID"); val != nil {
		tenantID = val.(string)
	}
	environment := ""
	if val := c.Locals("environment"); val != nil {
		environment = val.(string)
	}
	clientIP := c.IP()
	userAgent := c.Get("User-Agent")

	res, err := h.svc.RotateRefreshToken(c.UserContext(), tenantID, environment, rawToken, clientIP, userAgent)
	if err != nil {
		// Each message is the sentinel's own package-constant text, not err.Error(),
		// so a wrapped driver error reaching this path cannot be echoed back.
		if errors.Is(err, ErrSessionCompromised) {
			return httperr.Unauthorized(c, codeSessionCompromised, ErrSessionCompromised.Error())
		}
		if errors.Is(err, ErrSessionRevoked) {
			return httperr.Unauthorized(c, codeSessionRevoked, ErrSessionRevoked.Error())
		}
		if errors.Is(err, ErrSessionExpired) {
			return httperr.Unauthorized(c, httperr.CodeSessionExpired, ErrSessionExpired.Error())
		}
		if errors.Is(err, ErrSessionNotFound) {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken, "invalid or expired refresh token")
		}
		return httperr.SendInternal(c, "session.refresh", err)
	}

	return c.JSON(res)
}

func (h *Handler) AdminListUserSessions(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")

	sessions, err := h.svc.ListUserSessions(c.UserContext(), targetUserID, "")
	if err != nil {
		return httperr.SendInternal(c, "session.admin_list", err)
	}

	return c.JSON(fiber.Map{"sessions": sessions})
}

func (h *Handler) AdminRevokeAllUserSessions(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")

	count, err := h.svc.RevokeAllSessions(c.UserContext(), targetUserID)
	if err != nil {
		return httperr.SendInternal(c, "session.admin_revoke_all", err)
	}

	return c.JSON(fiber.Map{"message": "all sessions revoked for user", "user_id": targetUserID, "count": count})
}
