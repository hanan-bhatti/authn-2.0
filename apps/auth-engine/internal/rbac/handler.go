/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/handler.go
 * Tier: HTTP Delivery Layer (Fiber Handlers)
 *
 * Description: HTTP handlers for RBAC role creation, permission updates, role assignments,
 *              and client user permission evaluation endpoints.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes registers all RBAC HTTP routes on the Fiber application.
func (h *Handler) RegisterRoutes(app *fiber.App, tenantAdminMiddleware, clientAuthMiddleware fiber.Handler) {
	// Tenant endpoints (/v1/tenant/roles)
	tenantGroup := app.Group("/v1/tenant")
	if tenantAdminMiddleware != nil {
		tenantGroup.Use(tenantAdminMiddleware)
	}
	tenantGroup.Post("/roles", h.CreateRole)
	tenantGroup.Get("/roles", h.ListRoles)
	tenantGroup.Put("/roles/:role_id/permissions", h.UpdateRolePermissions)

	// Admin endpoints (/v1/admin/users/:user_id/roles)
	adminGroup := app.Group("/v1/admin")
	if tenantAdminMiddleware != nil {
		adminGroup.Use(tenantAdminMiddleware)
	}
	adminGroup.Post("/users/:user_id/roles", h.AssignUserRole)
	adminGroup.Delete("/users/:user_id/roles/:role_slug", h.RevokeUserRole)

	// Client user permission endpoint (/v1/client/user/permissions)
	clientGroup := app.Group("/v1/client")
	if clientAuthMiddleware != nil {
		clientGroup.Use(clientAuthMiddleware)
	}
	clientGroup.Get("/user/permissions", h.GetUserPermissions)
}

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
			claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.svc.cfg.AuthnEncryptionKey)
			if err == nil && claims != nil && claims.Sub != "" {
				return claims.Sub
			}
		}
	}
	return "admin_system"
}

func (h *Handler) CreateRole(c *fiber.Ctx) error {
	var req struct {
		TenantID    string   `json:"tenant_id"`
		Name        string   `json:"name"`
		Slug        string   `json:"slug"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	tenantID := req.TenantID
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = c.Query("tenant_id", "tnt_default")
		}
	}

	actorID := h.getActorID(c)
	roleObj, err := h.svc.CreateRole(c.UserContext(), tenantID, req.Name, req.Slug, req.Description, req.Permissions, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvalidPermissionFormat) || errors.Is(err, ErrInvalidActionVerb) || errors.Is(err, ErrRestrictedPermission) {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, ErrRoleExists) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(roleObj)
}

func (h *Handler) ListRoles(c *fiber.Ctx) error {
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_default"
		}
	}

	roles, err := h.svc.ListRoles(c.UserContext(), tenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"roles": roles})
}

func (h *Handler) UpdateRolePermissions(c *fiber.Ctx) error {
	roleID := c.Params("role_id")
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_default"
		}
	}

	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	actorID := h.getActorID(c)
	err := h.svc.UpdateRolePermissions(c.UserContext(), tenantID, roleID, req.Permissions, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrInvalidPermissionFormat) || errors.Is(err, ErrInvalidActionVerb) || errors.Is(err, ErrRestrictedPermission) {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "permissions updated successfully", "role_id": roleID})
}

func (h *Handler) AssignUserRole(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_default"
		}
	}

	var req struct {
		RoleSlug string `json:"role_slug"`
		Role     string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	roleSlug := req.RoleSlug
	if roleSlug == "" {
		roleSlug = req.Role
	}

	actorID := h.getActorID(c)
	err := h.svc.AssignUserRole(c.UserContext(), tenantID, targetUserID, roleSlug, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if errors.Is(err, ErrUserRoleExists) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, ErrRoleNotFound) || ent.IsNotFound(err) || ent.IsConstraintError(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user or role not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "role assigned to user successfully", "user_id": targetUserID, "role": roleSlug})
}

func (h *Handler) RevokeUserRole(c *fiber.Ctx) error {
	targetUserID := c.Params("user_id")
	roleSlug := c.Params("role_slug")
	tenantID := c.Query("tenant_id")
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_default"
		}
	}

	actorID := h.getActorID(c)
	err := h.svc.RevokeUserRole(c.UserContext(), tenantID, targetUserID, roleSlug, actorID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "role revoked from user successfully", "user_id": targetUserID, "role": roleSlug})
}

func (h *Handler) GetUserPermissions(c *fiber.Ctx) error {
	actorID := h.getActorID(c)
	if actorID == "" || actorID == "admin_system" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "session authentication required"})
	}

	roles, perms, err := h.svc.GetUserRBAC(c.UserContext(), actorID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"user_id":     actorID,
		"roles":       roles,
		"permissions": perms,
	})
}
