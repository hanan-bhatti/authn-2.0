/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/org_member_handlers.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber handlers for organization membership management and invitation response endpoints.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// ListMembers returns an organization's members. Answers 404 when the
// organization does not exist and 403 when the caller is not a member.
func (h *Handler) ListMembers(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	orgID := c.Params("orgId")
	actorID := getUserID(c)
	isAdmin := isAdminTier(c)

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	members, err := h.service.ListOrgMembers(c.UserContext(), tenantID, orgID, actorID, isAdmin, limit, offset)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.list_members", err)
	}

	return c.JSON(fiber.Map{
		"members": members,
		"total":   len(members),
	})
}

// AddMember places a user in an organization. Answers 201, 404 when the
// organization does not exist, 403 without org_admin, and 400 when the user is
// already a member or the role is invalid.
func (h *Handler) AddMember(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	userID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	var req AddMemberRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.AddMember(c.UserContext(), tenantID, userID, orgID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if errors.Is(err, ErrMemberAlreadyExists) {
			return httperr.BadRequest(c, httperr.CodeAlreadyExists, ErrMemberAlreadyExists.Error())
		}
		if errors.Is(err, ErrInvalidRole) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrInvalidRole.Error())
		}
		return httperr.SendInternal(c, "org.add_member", err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

// UpdateMemberRole changes a member's role. Answers 404 when the membership does
// not exist, 403 without org_admin, and 400 for an invalid role.
func (h *Handler) UpdateMemberRole(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	targetUserID := c.Params("userId")
	isAdmin := isAdminTier(c)

	var req UpdateMemberRoleRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.UpdateMemberRole(c.UserContext(), tenantID, actorID, orgID, targetUserID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "member not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if errors.Is(err, ErrInvalidRole) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrInvalidRole.Error())
		}
		return httperr.SendInternal(c, "org.update_member_role", err)
	}

	return c.JSON(resp)
}

// RemoveMember removes a user from an organization. Answers 404 when the
// membership does not exist and 403 without org_admin.
func (h *Handler) RemoveMember(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	targetUserID := c.Params("userId")
	isAdmin := isAdminTier(c)

	err := h.service.RemoveMember(c.UserContext(), tenantID, actorID, orgID, targetUserID, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "member not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.remove_member", err)
	}

	return c.JSON(fiber.Map{
		"message": "member removed successfully",
		"user_id": targetUserID,
		"org_id":  orgID,
	})
}

// CreateInvitation issues an invitation to join an organization, returning it
// with its redemption token. Answers 201, 404 when the organization does not
// exist, 403 without org_admin, and 400 for an invalid email or role.
func (h *Handler) CreateInvitation(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	var req CreateInvitationRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.CreateInvitation(c.UserContext(), tenantID, actorID, orgID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if errors.Is(err, ErrInvalidEmail) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrInvalidEmail.Error())
		}
		if errors.Is(err, ErrInvalidRole) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrInvalidRole.Error())
		}
		return httperr.SendInternal(c, "org.create_invitation", err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

// ListPendingInvitations returns an organization's outstanding invitations,
// without their tokens. Answers 404 when the organization does not exist and 403
// when the caller is not a member.
func (h *Handler) ListPendingInvitations(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	orgID := c.Params("orgId")
	actorID := getUserID(c)
	isAdmin := isAdminTier(c)

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	resps, err := h.service.ListPendingInvitations(c.UserContext(), tenantID, orgID, actorID, isAdmin, limit, offset)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.list_invitations", err)
	}

	return c.JSON(fiber.Map{
		"invitations": resps,
		"total":       len(resps),
	})
}

// RevokeInvitation cancels a pending invitation. Answers 404 when it does not
// exist, 403 without org_admin, and 400 when it is not in a revocable state.
func (h *Handler) RevokeInvitation(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	invitationID := c.Params("invitationId")
	isAdmin := isAdminTier(c)

	err := h.service.RevokeInvitation(c.UserContext(), tenantID, actorID, orgID, invitationID, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "invitation not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		// The expected case is a non-pending invitation, but this branch can also
		// see wrapped ent errors, so the message is static and the real error
		// stays in the log.
		return badRequestLogged(c, "org.revoke_invitation", err, httperr.CodeConflict,
			"invitation cannot be revoked in its current state")
	}

	return c.JSON(fiber.Map{
		"message":       "invitation revoked successfully",
		"invitation_id": invitationID,
	})
}

// AcceptInvitation redeems an invitation token into a membership. Answers 404 for
// an unknown token and 400 when the invitation is expired, already accepted, or
// belongs to the environment the caller is not signed in against.
func (h *Handler) AcceptInvitation(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	userID := getUserID(c)

	var req AcceptInvitationRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.AcceptInvitation(c.UserContext(), tenantID, userID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "invitation token not found")
		}
		if errors.Is(err, ErrInvitationExpired) {
			return httperr.BadRequest(c, httperr.CodeConflict, ErrInvitationExpired.Error())
		}
		if errors.Is(err, ErrInvitationAccepted) {
			return httperr.BadRequest(c, httperr.CodeConflict, ErrInvitationAccepted.Error())
		}
		if errors.Is(err, ErrInvitationEnvironmentMismatch) {
			return httperr.BadRequest(c, httperr.CodeConflict, ErrInvitationEnvironmentMismatch.Error())
		}
		return httperr.SendInternal(c, "org.accept_invitation", err)
	}

	return c.JSON(fiber.Map{
		"message": "invitation accepted successfully",
		"member":  resp,
	})
}
