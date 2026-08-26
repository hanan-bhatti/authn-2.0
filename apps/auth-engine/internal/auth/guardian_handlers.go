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
	"errors"

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

	// The application's own origin, resolved the same way an emailed link's is. The
	// guardian opens this in a browser, so it has to address the frontend: the
	// engine serves no pages, and a link to its host is a 404 for the one person
	// whose click the whole enrolment depends on.
	baseURL := h.service.FrontendBaseURL(c.UserContext())
	res, err := h.guardianService.InviteGuardians(c.UserContext(), userID, req.Guardians, baseURL)
	if err != nil {
		return sendServiceError(c, "auth.guardians.invite", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to invite the requested guardians")
	}

	return c.Status(fiber.StatusCreated).JSON(res)
}

// AcceptGuardianInvite handles POST /v1/client/account/guardians/accept.
//
// Public, and necessarily so: the caller is the guardian, a third party who has no session on the
// account they are agreeing to help recover. The invitation token is the authentication.
func (h *Handler) AcceptGuardianInvite(c *fiber.Ctx) error {
	var req struct {
		ContactID string `json:"contact_id"`
		Token     string `json:"token"`
		Share     string `json:"share"`
	}
	if err := c.BodyParser(&req); err != nil || req.ContactID == "" || req.Token == "" || req.Share == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "contact_id, token and share are required")
	}

	if err := h.guardianService.AcceptGuardianInvite(c.UserContext(), req.ContactID, req.Token, req.Share); err != nil {
		// A guardian who is already active is a conflict rather than a bad credential: the
		// link was genuine, it has simply been spent. The usual caller is that guardian
		// reopening their own link, and a 400 would have their client report a broken link.
		status := fiber.StatusBadRequest
		if errors.Is(err, ErrGuardianInviteNotPending) {
			status = fiber.StatusConflict
		}
		return sendServiceError(c, "auth.guardians.accept", status, err,
			httperr.CodeInvalidToken, "invalid or expired guardian invitation")
	}

	return c.JSON(fiber.Map{
		"message": "Guardian invitation accepted successfully",
	})
}

// ListGuardians handles GET /v1/client/account/guardians.
func (h *Handler) ListGuardians(c *fiber.Ctx) error {
	userID := getUserID(c)

	dtos, err := h.guardianService.ListGuardians(c.UserContext(), userID)
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

	if err := h.guardianService.RevokeGuardian(c.UserContext(), userID, contactID); err != nil {
		return sendServiceError(c, "auth.guardians.revoke", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to revoke this guardian")
	}

	return c.JSON(fiber.Map{
		"message": "Guardian revoked successfully. The remaining guardians keep the shares they already hold.",
	})
}
