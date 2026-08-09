/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/handler.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber handlers for the organization API across two tiers: the client
 *              surface (/v1/client/organizations) used by end users, and the tenant-admin
 *              surface (/v1/tenant/organizations). Resolves tenant and actor from
 *              middleware locals and maps the package sentinels onto the canonical error
 *              envelope; per-operation authorization lives in the service.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"errors"
	"log"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
)

// Handler exposes the organization service over HTTP.
type Handler struct {
	// service carries out the operation behind each route.
	service *Service
}

// NewHandler constructs an organization Handler over service.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes mounts the client and tenant-admin organization routes.
//
// Client routes require both a publishable key, which resolves the tenant, and an
// authenticated end-user session, which establishes the actor the service checks
// membership for. Without the session middleware these routes would be reachable
// with only a public pk_ key. Tenant routes sit behind the admin middleware
// instead. Per-operation authorization — member for reads, org_admin for
// mutations — is enforced inside the service.
func (h *Handler) RegisterRoutes(app *fiber.App, clientAuthMw fiber.Handler, pkMiddleware fiber.Handler, adminMiddleware fiber.Handler) {
	clientGroup := app.Group("/v1/client", pkMiddleware)
	if clientAuthMw != nil {
		clientGroup.Use(clientAuthMw)
	}

	clientGroup.Post("/organizations", h.CreateOrganization)
	clientGroup.Get("/organizations", h.ListUserOrganizations)
	clientGroup.Get("/organizations/:orgId", h.GetOrganization)
	clientGroup.Patch("/organizations/:orgId", h.UpdateOrganization)
	clientGroup.Delete("/organizations/:orgId", h.DeleteOrganization)

	clientGroup.Get("/organizations/:orgId/members", h.ListMembers)
	clientGroup.Post("/organizations/:orgId/members", h.AddMember)
	clientGroup.Patch("/organizations/:orgId/members/:userId", h.UpdateMemberRole)
	clientGroup.Delete("/organizations/:orgId/members/:userId", h.RemoveMember)

	clientGroup.Post("/organizations/:orgId/invitations", h.CreateInvitation)
	clientGroup.Get("/organizations/:orgId/invitations", h.ListPendingInvitations)
	clientGroup.Delete("/organizations/:orgId/invitations/:invitationId", h.RevokeInvitation)
	clientGroup.Post("/invitations/accept", h.AcceptInvitation)

	tenantGroup := app.Group("/v1/tenant", adminMiddleware)
	tenantGroup.Get("/organizations", h.TenantListOrganizations)
	tenantGroup.Get("/organizations/:orgId", h.TenantGetOrganization)
	tenantGroup.Post("/organizations", h.TenantCreateOrganization)
	tenantGroup.Delete("/organizations/:orgId", h.TenantDeleteOrganization)
}

// getTenantID returns the tenant resolved by the authenticating middleware, or
// "" when none was resolved.
//
// There is deliberately no default tenant: a request that reaches a handler with
// no resolved tenant is not authenticated, and substituting one would turn a
// middleware misconfiguration into a cross-tenant read or write.
func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenantID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// requireTenantID returns the resolved tenant, or a written 401 response when the
// tenant is unknown. Callers must return the response as-is when ok is false.
//
// Every route here sits behind the publishable-key or admin middleware, both of
// which set the tenant on success and reject the request otherwise, so an empty
// tenant means the request was never authenticated.
func requireTenantID(c *fiber.Ctx) (string, error, bool) {
	tenantID := getTenantID(c)
	if tenantID == "" {
		return "", httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request"), false
	}
	return tenantID, nil, true
}

// getUserID returns the authenticated end user driving the request, or "" when
// there is none. The service treats an empty actor as unauthorized.
func getUserID(c *fiber.Ctx) string {
	return rbac.ExtractUserID(c)
}

// isAdminTier reports whether the request authenticated through the tenant-admin
// middleware rather than an end-user session.
//
// Admin-tier callers operate across every organization in the tenant, so they
// bypass the per-organization membership and role checks. The signal is set
// exclusively by the admin middleware and cannot be produced from the client
// tier, so it cannot be spoofed; absent it, this returns false and the caller
// fails closed into the normal checks.
func isAdminTier(c *fiber.Ctx) bool {
	if val, ok := c.Locals("admin_auth_method").(string); ok && val != "" {
		return true
	}
	return false
}

// mapAuthzErr maps the authorization sentinels to a 403.
//
// Returns (response, true) when err was an authorization error and a response was
// written, or (nil, false) when the caller should continue its own mapping.
func mapAuthzErr(c *fiber.Ctx, err error) (error, bool) {
	switch {
	case errors.Is(err, ErrNotAMember):
		return httperr.Forbidden(c, httperr.CodeForbidden, ErrNotAMember.Error()), true
	case errors.Is(err, ErrForbidden):
		return httperr.Forbidden(c, httperr.CodeForbidden, ErrForbidden.Error()), true
	}
	return nil, false
}

// mapOrgValidationErr maps the validation and uniqueness sentinels to a 400
// carrying the sentinel's own client-safe text.
//
// Returns (response, true) when err matched. Matching is by sentinel identity
// rather than by substring, so a wrapped database error whose driver text happens
// to contain "exists" can never be downgraded to a 400.
func mapOrgValidationErr(c *fiber.Ctx, err error) (error, bool) {
	switch {
	case errors.Is(err, ErrOrgSlugExists):
		return httperr.BadRequest(c, httperr.CodeAlreadyExists, ErrOrgSlugExists.Error()), true
	case errors.Is(err, ErrInvalidOrgName):
		return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrInvalidOrgName.Error()), true
	case errors.Is(err, ErrInvalidOrgSlug):
		return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrInvalidOrgSlug.Error()), true
	case errors.Is(err, ErrInvalidLogoURL):
		return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrInvalidLogoURL.Error()), true
	case errors.Is(err, ErrMetadataTooLarge):
		return httperr.BadRequest(c, httperr.CodeValidationFailed, ErrMetadataTooLarge.Error()), true
	}
	return nil, false
}

// badRequestLogged answers with a 400 carrying a static, client-safe message
// while keeping the underlying error server-side.
//
// It serves the branches that answer 4xx but can still receive wrapped ent/SQL
// errors, which would otherwise disclose table and column names to the caller.
func badRequestLogged(c *fiber.Ctx, op string, err error, code httperr.Code, msg string) error {
	if err != nil {
		log.Printf("[error] %s %s %s: %v", c.Method(), c.Path(), op, err)
	}
	return httperr.BadRequest(c, code, msg)
}

// CreateOrganization creates an organization owned by the calling user, who
// becomes its first org_admin. Answers 201, or 400 for a validation failure.
func (h *Handler) CreateOrganization(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	userID := getUserID(c)

	var req CreateOrgRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.CreateOrganization(c.UserContext(), tenantID, userID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if resp, handled := mapOrgValidationErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.create", err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

// GetOrganization returns one organization. Answers 404 when it does not exist
// and 403 when the caller is not a member.
func (h *Handler) GetOrganization(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	orgID := c.Params("orgId")
	actorID := getUserID(c)
	isAdmin := isAdminTier(c)

	resp, err := h.service.GetOrganization(c.UserContext(), tenantID, orgID, actorID, isAdmin)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.get", err)
	}

	return c.JSON(resp)
}

// ListUserOrganizations returns the organizations the calling user belongs to.
func (h *Handler) ListUserOrganizations(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	userID := getUserID(c)

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	resps, err := h.service.ListOrganizationsForUser(c.UserContext(), tenantID, userID, limit, offset)
	if err != nil {
		return httperr.SendInternal(c, "org.list_for_user", err)
	}

	return c.JSON(fiber.Map{
		"organizations": resps,
		"total":         len(resps),
	})
}

// UpdateOrganization applies a partial update. Answers 404 when the organization
// does not exist, 403 without org_admin, and 400 for a validation failure.
func (h *Handler) UpdateOrganization(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	userID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	var req UpdateOrgRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.UpdateOrganization(c.UserContext(), tenantID, userID, orgID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if resp, handled := mapOrgValidationErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.update", err)
	}

	return c.JSON(resp)
}

// DeleteOrganization removes an organization and its dependents. Answers 404 when
// it does not exist and 403 without org_admin.
func (h *Handler) DeleteOrganization(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	userID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	err := h.service.DeleteOrganization(c.UserContext(), tenantID, userID, orgID, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "organization not found")
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.delete", err)
	}

	return c.JSON(fiber.Map{
		"message": "organization deleted successfully",
		"org_id":  orgID,
	})
}

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
// an unknown token and 400 when the invitation is expired or already accepted.
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
		return httperr.SendInternal(c, "org.accept_invitation", err)
	}

	return c.JSON(fiber.Map{
		"message": "invitation accepted successfully",
		"member":  resp,
	})
}

// TenantListOrganizations returns every organization in the tenant.
func (h *Handler) TenantListOrganizations(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	resps, err := h.service.ListOrganizationsForTenant(c.UserContext(), tenantID, limit, offset)
	if err != nil {
		return httperr.SendInternal(c, "org.tenant_list", err)
	}

	return c.JSON(fiber.Map{
		"organizations": resps,
		"total":         len(resps),
	})
}

// TenantGetOrganization returns one organization on the tenant-admin tier.
//
// It delegates to the client handler, which reads the admin signal set by the
// admin middleware this route is mounted behind and skips the membership check on
// that basis. Were the signal ever absent the delegate would fail closed with a
// 403 rather than open, and its tenant guard still runs.
func (h *Handler) TenantGetOrganization(c *fiber.Ctx) error {
	return h.GetOrganization(c)
}

// TenantCreateOrganization creates an organization on the tenant-admin tier,
// attributed to the admin actor rather than to an end user. Answers 201, or 400
// for a validation failure.
func (h *Handler) TenantCreateOrganization(c *fiber.Ctx) error {
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	actorID := "admin"

	var req CreateOrgRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	resp, err := h.service.CreateOrganization(c.UserContext(), tenantID, actorID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if resp, handled := mapOrgValidationErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.tenant_create", err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

// TenantDeleteOrganization removes an organization on the tenant-admin tier.
// It delegates to the client handler on the same basis as TenantGetOrganization.
func (h *Handler) TenantDeleteOrganization(c *fiber.Ctx) error {
	return h.DeleteOrganization(c)
}
