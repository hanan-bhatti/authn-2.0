/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/org_handlers.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber handlers for client and tenant-admin organization CRUD endpoints.
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
