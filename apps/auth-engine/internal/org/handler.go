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
	clientGroup.Get("/invitations", h.ListMyInvitations)
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

// mapOrgConflictErr maps the sentinels that report a refusal grounded in the
// organization's present state rather than in the request or the caller's rights.
//
// 409 rather than 403: the caller is permitted to make this call and the body is
// well-formed. What stands in the way is a condition the caller can change — an
// organization with exactly one administrator — and then retry, which is the
// distinction 409 carries and 403 does not.
//
// Returns (response, true) when err matched.
func mapOrgConflictErr(c *fiber.Ctx, err error) (error, bool) {
	if errors.Is(err, ErrLastOrgAdmin) {
		return httperr.Conflict(c, httperr.CodeConflict, ErrLastOrgAdmin.Error()), true
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
