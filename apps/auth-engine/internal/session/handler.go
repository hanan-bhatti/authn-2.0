/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/handler.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber handlers for the client session API (/v1/client/sessions), the token
 *              refresh endpoint, and the tenant-admin session endpoints. Resolves the
 *              calling identity from middleware locals or the bearer token, and maps the
 *              session sentinels onto the canonical error envelope.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Refresh-failure codes specific to this endpoint. They are part of the published
// wire contract the SDK branches on, so renaming one is a breaking API change.
const (
	// codeSessionCompromised marks a refusal caused by refresh-token reuse.
	codeSessionCompromised httperr.Code = "session_compromised"
	// codeSessionRevoked marks a refusal caused by an explicitly revoked session.
	codeSessionRevoked httperr.Code = "session_revoked"
)

// msgSessionAuthRequired is the single 401 message used by every client session
// endpoint. It is identical across handlers so a caller cannot distinguish
// "no token supplied" from "token rejected".
const msgSessionAuthRequired = "session authentication required: missing or invalid access token"

// Handler exposes the session service over HTTP.
type Handler struct {
	// svc carries out the session operations behind each route.
	svc *Service
}

// NewHandler constructs a session Handler over svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes mounts the client, refresh and admin session routes.
//
// pkMiddleware guards the client tier and resolves the tenant; adminMiddleware
// guards the admin tier, whose routes act on an arbitrary user ID from the path
// and therefore must never be reachable from a client session.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware, adminMiddleware fiber.Handler) {
	client := app.Group("/v1/client/sessions", pkMiddleware)
	client.Get("/", h.ListSessions)
	client.Post("/revoke", h.RevokeSession)
	client.Post("/revoke-others", h.RevokeOtherSessions)
	client.Post("/revoke-all", h.RevokeAllSessions)

	app.Post("/v1/client/auth/refresh", pkMiddleware, h.RefreshTokens)

	admin := app.Group("/v1/admin/users/:user_id/sessions", adminMiddleware)
	admin.Get("/", h.AdminListUserSessions)
	admin.Post("/revoke-all", h.AdminRevokeAllUserSessions)
}

// getUserIDAndSessionID resolves the calling user and session, preferring the
// locals set by authenticating middleware and falling back to the bearer token.
//
// The fallback verifies the token's signature before trusting any claim, so an
// unsigned or tampered token contributes nothing. Either value may come back
// empty; callers treat an empty user ID as unauthenticated.
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

	if userID == "" || sessionID == "" {
		authHeader := c.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.svc.cfg.EncryptionKey)
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

// ListSessions returns the caller's active sessions, flagging the current one.
// Answers 401 when the caller is unauthenticated.
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

// RevokeSession revokes one of the caller's own sessions, named in the body.
// Answers 400 without a session_id, 401 when unauthenticated, 404 when the
// session does not exist, and 403 when it belongs to another user.
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

// RevokeOtherSessions revokes all of the caller's sessions except the current
// one and reports how many were revoked. Answers 401 when unauthenticated.
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

// RevokeAllSessions revokes every session belonging to the caller, the current
// one included, and reports how many were revoked. Answers 401 when
// unauthenticated.
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

// RefreshTokens exchanges a refresh token, taken from the body or the
// authn_refresh_token cookie, for a new token pair.
//
// Answers 400 when no token was supplied and 401 for every rejection: reuse,
// revocation, expiry, or an unrecognised token. Each message is the sentinel's
// own package-constant text rather than err.Error(), so a wrapped driver error
// reaching this path cannot be echoed back to the caller.
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

// AdminListUserSessions returns the active sessions of the user named in the
// path. No session is marked current, because the admin caller is not one of them.
func (h *Handler) AdminListUserSessions(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")

	sessions, err := h.svc.ListUserSessions(c.UserContext(), targetUserID, "")
	if err != nil {
		return httperr.SendInternal(c, "session.admin_list", err)
	}

	return c.JSON(fiber.Map{"sessions": sessions})
}

// AdminRevokeAllUserSessions revokes every session of the user named in the path
// and reports how many were revoked.
func (h *Handler) AdminRevokeAllUserSessions(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")

	count, err := h.svc.RevokeAllSessions(c.UserContext(), targetUserID)
	if err != nil {
		return httperr.SendInternal(c, "session.admin_revoke_all", err)
	}

	return c.JSON(fiber.Map{"message": "all sessions revoked for user", "user_id": targetUserID, "count": count})
}
