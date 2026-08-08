/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/handler.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber HTTP handlers exposing Client (/v1/client/organizations/...) and
 *              Tenant Admin (/v1/tenant/organizations/...) REST API endpoints for B2B
 *              Organizations & Team Member Invitations (FR-15).
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

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes registers all Client and Tenant Admin routes with appropriate middleware guards.
//
// Client routes require BOTH a valid publishable key (pkMiddleware, which resolves the
// tenant) AND an authenticated end-user session (clientAuthMw, which sets the userID local).
// Without clientAuthMw every route below was reachable with only a public pk_ key — the
// C1 vulnerability. Per-operation authorization (member vs org_admin) is enforced inside
// each handler via the service's Authorize* guards (C2).
func (h *Handler) RegisterRoutes(app *fiber.App, clientAuthMw fiber.Handler, pkMiddleware fiber.Handler, adminMiddleware fiber.Handler) {
	// Client API routes (/v1/client/organizations) — requires Publishable Key AND User Identity
	clientGroup := app.Group("/v1/client", pkMiddleware)
	if clientAuthMw != nil {
		clientGroup.Use(clientAuthMw)
	}

	// Organization CRUD (Client)
	clientGroup.Post("/organizations", h.CreateOrganization)
	clientGroup.Get("/organizations", h.ListUserOrganizations)
	clientGroup.Get("/organizations/:orgId", h.GetOrganization)
	clientGroup.Patch("/organizations/:orgId", h.UpdateOrganization)
	clientGroup.Delete("/organizations/:orgId", h.DeleteOrganization)

	// Org Member Management (Client)
	clientGroup.Get("/organizations/:orgId/members", h.ListMembers)
	clientGroup.Post("/organizations/:orgId/members", h.AddMember)
	clientGroup.Patch("/organizations/:orgId/members/:userId", h.UpdateMemberRole)
	clientGroup.Delete("/organizations/:orgId/members/:userId", h.RemoveMember)

	// Org Invitation Management (Client)
	clientGroup.Post("/organizations/:orgId/invitations", h.CreateInvitation)
	clientGroup.Get("/organizations/:orgId/invitations", h.ListPendingInvitations)
	clientGroup.Delete("/organizations/:orgId/invitations/:invitationId", h.RevokeInvitation)
	clientGroup.Post("/invitations/accept", h.AcceptInvitation)

	// Tenant Admin API routes (/v1/tenant/organizations) — requires Secret Key OR tenant_admin JWT
	tenantGroup := app.Group("/v1/tenant", adminMiddleware)
	tenantGroup.Get("/organizations", h.TenantListOrganizations)
	tenantGroup.Get("/organizations/:orgId", h.TenantGetOrganization)
	tenantGroup.Post("/organizations", h.TenantCreateOrganization)
	tenantGroup.Delete("/organizations/:orgId", h.TenantDeleteOrganization)
}

// Helpers

// getTenantID resolves the tenant for this request from the locals set by the
// authenticating middleware, or returns "" when no tenant could be resolved.
//
// M3: this helper used to fall back to the literal "tnt_default". A request that
// somehow reached a handler without a resolved tenant therefore did not fail — it
// silently read and wrote a real production tenant's organizations, turning a
// middleware misconfiguration into a cross-tenant data operation. It now fails
// closed and every call site rejects the request via requireTenantID.
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
// Every route in this file is mounted behind pkMiddleware (client tier) or
// adminMiddleware (tenant tier); both set the tenant_id local on success and
// reject the request outright otherwise. An empty tenant at this point therefore
// means the request was never properly authenticated, so 401 is the correct
// answer and no legitimate flow depends on the old silent fallback.
func requireTenantID(c *fiber.Ctx) (string, error, bool) {
	tenantID := getTenantID(c)
	if tenantID == "" {
		return "", httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request"), false
	}
	return tenantID, nil, true
}

func getUserID(c *fiber.Ctx) string {
	return rbac.ExtractUserID(c)
}

// isAdminTier reports whether the request was authenticated via the tenant-admin
// middleware (sk_ secret key or tenant_admin console JWT) rather than an end-user
// client session. Admin-tier callers legitimately operate across all orgs in the
// tenant, so they bypass the per-org membership/role checks enforced for client users.
// The signal is set exclusively by middleware.RequireAdminAuth — a client session
// can never set it, so this cannot be spoofed from the /v1/client tier.
func isAdminTier(c *fiber.Ctx) bool {
	if val, ok := c.Locals("admin_auth_method").(string); ok && val != "" {
		return true
	}
	return false
}

// mapAuthzErr maps the org authorization sentinels (ErrNotAMember, ErrForbidden) to a
// 403 response. Returns (response, true) when err was an authorization error and a
// response was written; (nil, false) when the caller should continue its own mapping.
func mapAuthzErr(c *fiber.Ctx, err error) (error, bool) {
	switch {
	case errors.Is(err, ErrNotAMember):
		return httperr.Forbidden(c, httperr.CodeForbidden, ErrNotAMember.Error()), true
	case errors.Is(err, ErrForbidden):
		return httperr.Forbidden(c, httperr.CodeForbidden, ErrForbidden.Error()), true
	}
	return nil, false
}

// mapOrgValidationErr maps the request-validation and uniqueness sentinels to a 400
// with the sentinel's own (client-safe, package-constant) text. Returns
// (response, true) when err matched. Sentinel identity is used rather than
// substring matching on err.Error(), so a wrapped database error whose driver text
// happens to contain "exists" can never be downgraded to a 400.
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

// badRequestLogged answers with a 400 carrying a static, client-safe message while
// keeping the underlying error server-side.
//
// It exists for the legacy branches that must stay 4xx for API compatibility but
// can still receive wrapped ent/SQL errors. Returning err.Error() there leaked
// table and column names to callers; dropping err entirely would lose the only
// record of a real database failure, so it is logged in SendInternal's format.
func badRequestLogged(c *fiber.Ctx, op string, err error, code httperr.Code, msg string) error {
	if err != nil {
		log.Printf("[error] %s %s %s: %v", c.Method(), c.Path(), op, err)
	}
	return httperr.BadRequest(c, code, msg)
}

// Handlers Implementation

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
		// Kept at 400 for API compatibility: the expected case here is a non-pending
		// invitation. The branch can also see wrapped ent errors, so the message is
		// static and the real error stays in the server log.
		return badRequestLogged(c, "org.revoke_invitation", err, httperr.CodeConflict,
			"invitation cannot be revoked in its current state")
	}

	return c.JSON(fiber.Map{
		"message":       "invitation revoked successfully",
		"invitation_id": invitationID,
	})
}

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

// Tenant Admin Handlers

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

func (h *Handler) TenantGetOrganization(c *fiber.Ctx) error {
	// SAFE DELEGATION: Tenant routes are mounted under adminMiddleware (RequireAdminAuth),
	// which sets Locals("admin_auth_method"). GetOrganization reads isAdminTier(c) from that
	// local, so the per-org membership check is correctly bypassed here. If the admin local
	// were ever absent, isAdminTier returns false and the call fails CLOSED (403), never open.
	// The tenant guard (requireTenantID) also runs inside the delegate.
	return h.GetOrganization(c)
}

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
		// H8: this used to be strings.Contains(err.Error(), "exists"/"must be"), which
		// both misclassified ErrInvalidLogoURL as a 500 and would downgrade any wrapped
		// database error whose driver text happened to contain those words to a 400.
		if resp, handled := mapOrgValidationErr(c, err); handled {
			return resp
		}
		return httperr.SendInternal(c, "org.tenant_create", err)
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *Handler) TenantDeleteOrganization(c *fiber.Ctx) error {
	// SAFE DELEGATION: see TenantGetOrganization — adminMiddleware sets admin_auth_method,
	// so DeleteOrganization's isAdminTier(c) bypasses the org_admin check for the admin tier.
	// Fails CLOSED (403) if the admin local is ever absent.
	// The tenant guard (requireTenantID) also runs inside the delegate.
	return h.DeleteOrganization(c)
}
