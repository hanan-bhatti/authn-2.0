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
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
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
func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenantID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return "tnt_default"
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
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": ErrNotAMember.Error(), "code": "forbidden"}), true
	case errors.Is(err, ErrForbidden):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": ErrForbidden.Error(), "code": "forbidden"}), true
	}
	return nil, false
}

// Handlers Implementation

func (h *Handler) CreateOrganization(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	userID := getUserID(c)

	var req CreateOrgRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request JSON body",
		})
	}

	resp, err := h.service.CreateOrganization(c.UserContext(), tenantID, userID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgSlugExists) || errors.Is(err, ErrInvalidOrgName) || errors.Is(err, ErrInvalidOrgSlug) || errors.Is(err, ErrInvalidLogoURL) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *Handler) GetOrganization(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	orgID := c.Params("orgId")
	actorID := getUserID(c)
	isAdmin := isAdminTier(c)

	resp, err := h.service.GetOrganization(c.UserContext(), tenantID, orgID, actorID, isAdmin)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (h *Handler) ListUserOrganizations(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	userID := getUserID(c)

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	resps, err := h.service.ListOrganizationsForUser(c.UserContext(), tenantID, userID, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"organizations": resps,
		"total":         len(resps),
	})
}

func (h *Handler) UpdateOrganization(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	userID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	var req UpdateOrgRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.UpdateOrganization(c.UserContext(), tenantID, userID, orgID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if errors.Is(err, ErrOrgSlugExists) || errors.Is(err, ErrInvalidOrgName) || errors.Is(err, ErrInvalidOrgSlug) || errors.Is(err, ErrInvalidLogoURL) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (h *Handler) DeleteOrganization(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	userID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	err := h.service.DeleteOrganization(c.UserContext(), tenantID, userID, orgID, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"message": "organization deleted successfully",
		"org_id":  orgID,
	})
}

func (h *Handler) ListMembers(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	orgID := c.Params("orgId")
	actorID := getUserID(c)
	isAdmin := isAdminTier(c)

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	members, err := h.service.ListOrgMembers(c.UserContext(), tenantID, orgID, actorID, isAdmin, limit, offset)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"members": members,
		"total":   len(members),
	})
}

func (h *Handler) AddMember(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	userID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	var req AddMemberRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.AddMember(c.UserContext(), tenantID, userID, orgID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if errors.Is(err, ErrMemberAlreadyExists) || errors.Is(err, ErrInvalidRole) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *Handler) UpdateMemberRole(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	targetUserID := c.Params("userId")
	isAdmin := isAdminTier(c)

	var req UpdateMemberRoleRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.UpdateMemberRole(c.UserContext(), tenantID, actorID, orgID, targetUserID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "member not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if errors.Is(err, ErrInvalidRole) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (h *Handler) RemoveMember(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	targetUserID := c.Params("userId")
	isAdmin := isAdminTier(c)

	err := h.service.RemoveMember(c.UserContext(), tenantID, actorID, orgID, targetUserID, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "member not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"message": "member removed successfully",
		"user_id": targetUserID,
		"org_id":  orgID,
	})
}

func (h *Handler) CreateInvitation(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	isAdmin := isAdminTier(c)

	var req CreateInvitationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.CreateInvitation(c.UserContext(), tenantID, actorID, orgID, req, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		if errors.Is(err, ErrInvalidEmail) || errors.Is(err, ErrInvalidRole) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *Handler) ListPendingInvitations(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	orgID := c.Params("orgId")
	actorID := getUserID(c)
	isAdmin := isAdminTier(c)

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	resps, err := h.service.ListPendingInvitations(c.UserContext(), tenantID, orgID, actorID, isAdmin, limit, offset)
	if err != nil {
		if errors.Is(err, ErrOrgNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "organization not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"invitations": resps,
		"total":       len(resps),
	})
}

func (h *Handler) RevokeInvitation(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := getUserID(c)
	orgID := c.Params("orgId")
	invitationID := c.Params("invitationId")
	isAdmin := isAdminTier(c)

	err := h.service.RevokeInvitation(c.UserContext(), tenantID, actorID, orgID, invitationID, isAdmin, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invitation not found"})
		}
		if resp, handled := mapAuthzErr(c, err); handled {
			return resp
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"message":       "invitation revoked successfully",
		"invitation_id": invitationID,
	})
}

func (h *Handler) AcceptInvitation(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	userID := getUserID(c)

	var req AcceptInvitationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.AcceptInvitation(c.UserContext(), tenantID, userID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "invitation token not found"})
		}
		if errors.Is(err, ErrInvitationExpired) || errors.Is(err, ErrInvitationAccepted) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"message": "invitation accepted successfully",
		"member":  resp,
	})
}

// Tenant Admin Handlers

func (h *Handler) TenantListOrganizations(c *fiber.Ctx) error {
	tenantID := getTenantID(c)

	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	offset, _ := strconv.Atoi(c.Query("offset", "0"))

	resps, err := h.service.ListOrganizationsForTenant(c.UserContext(), tenantID, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
	return h.GetOrganization(c)
}

func (h *Handler) TenantCreateOrganization(c *fiber.Ctx) error {
	tenantID := getTenantID(c)
	actorID := "admin"

	var req CreateOrgRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request JSON body"})
	}

	resp, err := h.service.CreateOrganization(c.UserContext(), tenantID, actorID, req, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if strings.Contains(err.Error(), "exists") || strings.Contains(err.Error(), "must be") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (h *Handler) TenantDeleteOrganization(c *fiber.Ctx) error {
	// SAFE DELEGATION: see TenantGetOrganization — adminMiddleware sets admin_auth_method,
	// so DeleteOrganization's isAdminTier(c) bypasses the org_admin check for the admin tier.
	// Fails CLOSED (403) if the admin local is ever absent.
	return h.DeleteOrganization(c)
}
