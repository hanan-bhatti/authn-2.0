/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/handler.go
 * Tier: HTTP Delivery Layer (Fiber Handlers)
 *
 * HTTP endpoints for role management and permission inspection: role creation,
 * permission updates, user-role assignment and revocation on the admin surface,
 * and a caller's own effective permissions on the client surface.
 *
 * Validation failures are reported through fixed prose rather than the
 * underlying error text, because the sentinels are wrapped with the offending
 * permission, role slug and action verb — details of tenant policy that a
 * rejected caller has no claim to.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Handler serves the RBAC HTTP endpoints.
type Handler struct {
	// svc applies the RBAC business rules behind every endpoint.
	svc *Service
}

// NewHandler returns an RBAC handler bound to svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes mounts the RBAC endpoints.
//
// tenantAdminMiddleware guards the tenant and admin groups. The client group
// requires BOTH pkMiddleware and clientAuthMiddleware: a publishable key
// identifies the application but is public by design and establishes no user
// identity, so it can never on its own gate a route that reports a specific
// user's permissions. Passing the publishable-key middleware in the
// clientAuthMiddleware slot leaves that route effectively unauthenticated.
func (h *Handler) RegisterRoutes(app *fiber.App, tenantAdminMiddleware, clientAuthMiddleware, pkMiddleware fiber.Handler) {
	tenantGroup := app.Group("/v1/tenant")
	if tenantAdminMiddleware != nil {
		tenantGroup.Use(tenantAdminMiddleware)
	}
	tenantGroup.Post("/roles", h.CreateRole)
	tenantGroup.Get("/roles", h.ListRoles)
	tenantGroup.Put("/roles/:role_id/permissions", h.UpdateRolePermissions)

	adminGroup := app.Group("/v1/admin")
	if tenantAdminMiddleware != nil {
		adminGroup.Use(tenantAdminMiddleware)
	}
	adminGroup.Post("/users/:user_id/roles", h.AssignUserRole)
	adminGroup.Delete("/users/:user_id/roles/:role_slug", h.RevokeUserRole)

	clientGroup := app.Group("/v1/client")
	if pkMiddleware != nil {
		clientGroup.Use(pkMiddleware)
	}
	if clientAuthMiddleware != nil {
		clientGroup.Use(clientAuthMiddleware)
	}
	clientGroup.Get("/user/permissions", h.GetUserPermissions)
}

// getActorID resolves who is making the request, from the request locals when an
// auth middleware set them, otherwise by verifying the bearer token directly. It
// returns "admin_system" when no identity can be established, which endpoints
// acting on behalf of a specific user must treat as unauthenticated.
func (h *Handler) getActorID(c *fiber.Ctx) string {
	if val, ok := c.Locals("userID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("console_user_id").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("user_id").(string); ok && val != "" {
		return val
	}
	authHeader := c.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenStr := authHeader[7:]
		if h.svc != nil && h.svc.cfg != nil {
			claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.svc.cfg.EncryptionKey)
			if err == nil && claims != nil && claims.Sub != "" {
				return claims.Sub
			}
		}
	}
	return "admin_system"
}

// sendPermissionValidationError answers 422 with static prose for each
// permission-validation sentinel, defaulting to the restricted-permission
// message. The sentinels arrive wrapped with the offending permission, role slug
// and action verb, so relaying err.Error() would echo tenant policy internals to
// the caller.
func sendPermissionValidationError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrInvalidPermissionFormat):
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			"permission must follow format 'resource:action' (e.g. 'users:read', 'posts:create')")
	case errors.Is(err, ErrInvalidActionVerb):
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			"invalid action verb: must be read, write, create, update, delete, revoke, manage, execute, or *")
	default:
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			"permission assignment is restricted for this role under tenant policy")
	}
}

// CreateRole handles POST /v1/tenant/roles. It answers 201 with the new role,
// 400 for an unparseable body, 422 for a malformed or restricted permission, 409
// when the name or slug is taken, and 500 otherwise. The tenant comes from the
// body, then the authenticated context, then the query string.
func (h *Handler) CreateRole(c *fiber.Ctx) error {
	var req struct {
		TenantID    string   `json:"tenant_id"`
		Name        string   `json:"name"`
		Slug        string   `json:"slug"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	tenantID := req.TenantID
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = c.Query("tenant_id", "tnt_00000000000000000000000000000001")
		}
	}

	actorID := h.getActorID(c)
	roleObj, err := h.svc.CreateRole(c.UserContext(), tenantID, req.Name, req.Slug, req.Description, req.Permissions, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvalidPermissionFormat) || errors.Is(err, ErrInvalidActionVerb) || errors.Is(err, ErrRestrictedPermission) {
			return sendPermissionValidationError(c, err)
		}
		if errors.Is(err, ErrRoleExists) {
			return httperr.Conflict(c, httperr.CodeAlreadyExists,
				"role with this name or slug already exists in tenant")
		}
		return httperr.SendInternal(c, "rbac.create_role", err)
	}

	return c.Status(fiber.StatusCreated).JSON(roleObj)
}

// ListRoles handles GET /v1/tenant/roles, answering 200 with every role in the
// tenant and its permissions, or 500 when the query fails.
func (h *Handler) ListRoles(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_00000000000000000000000000000001"
		}
	}

	roles, err := h.svc.ListRoles(c.UserContext(), tenantID)
	if err != nil {
		return httperr.SendInternal(c, "rbac.list_roles", err)
	}

	return c.JSON(fiber.Map{"roles": roles})
}

// UpdateRolePermissions handles PUT /v1/tenant/roles/:role_id/permissions,
// replacing the role's permission set. It answers 200 on success, 400 for an
// unparseable body, 422 for a malformed or restricted permission, and 500
// otherwise.
func (h *Handler) UpdateRolePermissions(c *fiber.Ctx) error {
	roleID := c.Params("role_id")
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_00000000000000000000000000000001"
		}
	}

	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	actorID := h.getActorID(c)
	err := h.svc.UpdateRolePermissions(c.UserContext(), tenantID, roleID, req.Permissions, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvalidPermissionFormat) || errors.Is(err, ErrInvalidActionVerb) || errors.Is(err, ErrRestrictedPermission) {
			return sendPermissionValidationError(c, err)
		}
		return httperr.SendInternal(c, "rbac.update_role_permissions", err)
	}

	return c.JSON(fiber.Map{"message": "permissions updated successfully", "role_id": roleID})
}

// AssignUserRole handles POST /v1/admin/users/:user_id/roles. The role slug is
// read from role_slug, falling back to role. It answers 200 on success, 400 for
// an unparseable body, 409 when the user already holds the role, 404 when the
// user or role does not exist, and 500 otherwise.
func (h *Handler) AssignUserRole(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_00000000000000000000000000000001"
		}
	}

	var req struct {
		RoleSlug string `json:"role_slug"`
		Role     string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	roleSlug := req.RoleSlug
	if roleSlug == "" {
		roleSlug = req.Role
	}

	actorID := h.getActorID(c)
	err := h.svc.AssignUserRole(c.UserContext(), tenantID, targetUserID, roleSlug, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrUserRoleExists) {
			return httperr.Conflict(c, httperr.CodeAlreadyExists, "user already possesses this role")
		}
		if errors.Is(err, ErrRoleNotFound) || ent.IsNotFound(err) || ent.IsConstraintError(err) {
			return httperr.NotFound(c, httperr.CodeNotFound, "user or role not found")
		}
		return httperr.SendInternal(c, "rbac.assign_user_role", err)
	}

	return c.JSON(fiber.Map{"message": "role assigned to user successfully", "user_id": targetUserID, "role": roleSlug})
}

// RevokeUserRole handles DELETE /v1/admin/users/:user_id/roles/:role_slug,
// answering 200 on success and 500 when the revocation fails.
func (h *Handler) RevokeUserRole(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")
	roleSlug := c.Params("role_slug")
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_00000000000000000000000000000001"
		}
	}

	actorID := h.getActorID(c)
	err := h.svc.RevokeUserRole(c.UserContext(), tenantID, targetUserID, roleSlug, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) || errors.Is(err, ErrUserNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "user or role not found")
		}
		return httperr.SendInternal(c, "rbac.revoke_user_role", err)
	}

	return c.JSON(fiber.Map{"message": "role revoked from user successfully", "user_id": targetUserID, "role": roleSlug})
}

// GetUserPermissions handles GET /v1/client/user/permissions, reporting the
// caller's own roles and effective permissions.
//
// It answers 401 unless getActorID resolved a real user: the "admin_system"
// fallback identifies no one, and reporting a permission set for it would answer
// an unauthenticated request. Otherwise 200, or 500 when the lookup fails.
func (h *Handler) GetUserPermissions(c *fiber.Ctx) error {
	actorID := h.getActorID(c)
	if actorID == "" || actorID == "admin_system" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "session authentication required")
	}

	roles, perms, err := h.svc.GetUserRBAC(c.UserContext(), actorID)
	if err != nil {
		return httperr.SendInternal(c, "rbac.get_user_permissions", err)
	}

	return c.JSON(fiber.Map{
		"user_id":     actorID,
		"roles":       roles,
		"permissions": perms,
	})
}
