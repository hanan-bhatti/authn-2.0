/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/guardian_handlers.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber HTTP handlers for Social Recovery Guardians (invite, accept, list, revoke).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// InviteGuardians handles POST /v1/client/account/guardians/invite. Requires step-up re-auth / fresh session.
func (h *Handler) InviteGuardians(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req struct {
		Guardians []InviteGuardianInput `json:"guardians"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.Guardians) == 0 {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"Invalid payload: must provide 1 to 5 guardian email and name objects")
	}

	baseURL := fmt.Sprintf("%s://%s", c.Protocol(), c.Hostname())
	res, err := h.guardianService.InviteGuardians(c.Context(), userID, req.Guardians, baseURL)
	if err != nil {
		return sendServiceError(c, "auth.guardians.invite", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to invite the requested guardians")
	}

	return c.Status(fiber.StatusCreated).JSON(res)
}

// AcceptGuardianInvite handles POST /v1/client/account/guardians/accept.
func (h *Handler) AcceptGuardianInvite(c *fiber.Ctx) error {
	var req struct {
		ContactID string `json:"contact_id"`
		Token     string `json:"token"`
	}
	if err := c.BodyParser(&req); err != nil || req.ContactID == "" || req.Token == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "contact_id and token are required")
	}

	if err := h.guardianService.AcceptGuardianInvite(c.Context(), req.ContactID, req.Token); err != nil {
		return sendServiceError(c, "auth.guardians.accept", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, "invalid or expired guardian invitation")
	}

	return c.JSON(fiber.Map{
		"message": "Guardian invitation accepted successfully",
	})
}

// ListGuardians handles GET /v1/client/account/guardians.
func (h *Handler) ListGuardians(c *fiber.Ctx) error {
	userID := getUserID(c)

	dtos, err := h.guardianService.ListGuardians(c.Context(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.guardians.list", err)
	}

	return c.JSON(fiber.Map{
		"guardians": dtos,
	})
}

// RevokeGuardian handles DELETE /v1/client/account/guardians/:id.
func (h *Handler) RevokeGuardian(c *fiber.Ctx) error {
	userID := getUserID(c)

	contactID := c.Params("id")
	if contactID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "Guardian contact ID is required")
	}

	if err := h.guardianService.RevokeGuardian(c.Context(), userID, contactID); err != nil {
		return sendServiceError(c, "auth.guardians.revoke", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to revoke this guardian")
	}

	return c.JSON(fiber.Map{
		"message": "Guardian revoked successfully. Remaining guardians re-keyed with new Shamir shares.",
	})
}
