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
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

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

	// If userID is missing, try parsing Authorization Bearer <jwt>
	if userID == "" {
		authHeader := c.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.svc.cfg.AuthnEncryptionKey)
			if err == nil && claims != nil {
				userID = claims.Sub
			}
		}
	}

	return userID, sessionID
}

func (h *Handler) ListSessions(c *fiber.Ctx) error {
	userID, currentSessionID := h.getUserIDAndSessionID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session authentication required: missing or invalid access token"})
	}

	sessions, err := h.svc.ListUserSessions(c.UserContext(), userID, currentSessionID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"sessions": sessions})
}

func (h *Handler) RevokeSession(c *fiber.Ctx) error {
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	userID, _ := h.getUserIDAndSessionID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session authentication required: missing or invalid access token"})
	}

	err := h.svc.RevokeSession(c.UserContext(), userID, req.SessionID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "session revoked", "session_id": req.SessionID})
}

func (h *Handler) RevokeOtherSessions(c *fiber.Ctx) error {
	userID, currentSessionID := h.getUserIDAndSessionID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session authentication required: missing or invalid access token"})
	}

	count, err := h.svc.RevokeOtherSessions(c.UserContext(), userID, currentSessionID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "all other sessions revoked", "count": count})
}

func (h *Handler) RevokeAllSessions(c *fiber.Ctx) error {
	userID, _ := h.getUserIDAndSessionID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session authentication required: missing or invalid access token"})
	}

	count, err := h.svc.RevokeAllSessions(c.UserContext(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token required"})
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
		if errors.Is(err, ErrSessionCompromised) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error(), "code": "session_compromised"})
		}
		if errors.Is(err, ErrSessionRevoked) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error(), "code": "session_revoked"})
		}
		if errors.Is(err, ErrSessionExpired) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error(), "code": "session_expired"})
		}
		if errors.Is(err, ErrSessionNotFound) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid or expired refresh token", "code": "invalid_token"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(res)
}

func (h *Handler) AdminListUserSessions(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")

	sessions, err := h.svc.ListUserSessions(c.UserContext(), targetUserID, "")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"sessions": sessions})
}

func (h *Handler) AdminRevokeAllUserSessions(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")

	count, err := h.svc.RevokeAllSessions(c.UserContext(), targetUserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "all sessions revoked for user", "user_id": targetUserID, "count": count})
}
