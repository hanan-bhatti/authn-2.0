/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/repository.go
 * Tier: Database Persistence Layer
 *
 * Description: Data access repository for Role, Permission, and UserRole entities.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/permission"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

var (
	ErrRoleNotFound     = errors.New("role not found")
	ErrRoleExists       = errors.New("role with this name or slug already exists in tenant")
	ErrSystemRoleDelete = errors.New("built-in system roles cannot be deleted")
	ErrUserRoleExists   = errors.New("user already possesses this role")
)

type Repository struct {
	factory *clientfactory.ClientFactory
}

func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// CreateRole creates a new role entity in the database.
func (r *Repository) CreateRole(ctx context.Context, tenantID, name, slug, description string, isSystem bool, actorID string) (*ent.Role, error) {
	client := r.factory.GetClient(ctx, tenantID, "")

	roleName := name
	if roleName == "" {
		roleName = slug
	}
	roleSlug := slug
	if roleSlug == "" {
		// Auto-derive slug from name: lowercase + underscores
		roleSlug = strings.ToLower(strings.ReplaceAll(roleName, " ", "_"))
	}

	// Check name uniqueness
	nameExists, err := client.Role.Query().Where(role.TenantID(tenantID), role.Name(roleName)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if nameExists {
		return nil, ErrRoleExists
	}

	// Check slug uniqueness
	slugExists, err := client.Role.Query().Where(role.TenantID(tenantID), role.Slug(roleSlug)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if slugExists {
		return nil, ErrRoleExists
	}

	roleID := fmt.Sprintf("rol_%s", uuid.New().String()[:12])
	builder := client.Role.Create().
		SetID(roleID).
		SetTenantID(tenantID).
		SetName(roleName).
		SetSlug(roleSlug).
		SetIsSystemRole(isSystem)

	if description != "" {
		builder.SetDescription(description)
	}
	if actorID != "" {
		builder.SetCreatedByUserID(actorID)
	}

	return builder.Save(ctx)
}

// GetRoleByID retrieves a role by its unique ID.
func (r *Repository) GetRoleByID(ctx context.Context, roleID string) (*ent.Role, error) {
	client := r.factory.GetClient(ctx, "", "")
	roleObj, err := client.Role.Query().Where(role.ID(roleID)).WithPermissions().Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrRoleNotFound
	}
	return roleObj, err
}

// GetRoleBySlug retrieves a role by tenant ID and its slug field (exact match).
func (r *Repository) GetRoleBySlug(ctx context.Context, tenantID, slug string) (*ent.Role, error) {
	client := r.factory.GetClient(ctx, tenantID, "")
	roleObj, err := client.Role.Query().
		Where(
			role.TenantID(tenantID),
			role.Slug(slug),
		).
		WithPermissions().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrRoleNotFound
	}
	return roleObj, err
}

// ListRoles retrieves all roles for a given tenant.
func (r *Repository) ListRoles(ctx context.Context, tenantID string) ([]*ent.Role, error) {
	client := r.factory.GetClient(ctx, tenantID, "")
	return client.Role.Query().Where(role.TenantID(tenantID)).WithPermissions().All(ctx)
}

// UpdateRole updates role name/description.
func (r *Repository) UpdateRole(ctx context.Context, tenantID, roleID, name, description string, actorID string) (*ent.Role, error) {
	client := r.factory.GetClient(ctx, tenantID, "")
	builder := client.Role.UpdateOneID(roleID).SetName(name)

	if description != "" {
		builder.SetDescription(description)
	}
	if actorID != "" {
		builder.SetUpdatedByUserID(actorID)
	}

	return builder.Save(ctx)
}

// DeleteRole deletes a non-system role and its permission/user bindings.
func (r *Repository) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	client := r.factory.GetClient(ctx, tenantID, "")
	roleObj, err := r.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if roleObj.IsSystemRole {
		return ErrSystemRoleDelete
	}

	_, _ = client.Permission.Delete().Where(permission.RoleID(roleID)).Exec(ctx)
	_, _ = client.UserRole.Delete().Where(userrole.RoleID(roleID)).Exec(ctx)

	return client.Role.DeleteOneID(roleID).Exec(ctx)
}

// SetRolePermissions replaces all permissions for a role atomically.
func (r *Repository) SetRolePermissions(ctx context.Context, roleID string, perms []string, actorID string) error {
	client := r.factory.GetClient(ctx, "", "")

	_, err := client.Permission.Delete().Where(permission.RoleID(roleID)).Exec(ctx)
	if err != nil {
		return err
	}

	for _, p := range perms {
		prmID := fmt.Sprintf("prm_%s", uuid.New().String()[:12])
		builder := client.Permission.Create().
			SetID(prmID).
			SetRoleID(roleID).
			SetAction(p)

		if actorID != "" {
			builder.SetCreatedByUserID(actorID)
		}
		if _, err := builder.Save(ctx); err != nil {
			return err
		}
	}

	return nil
}

// AssignRoleToUser binds a role to a user.
func (r *Repository) AssignRoleToUser(ctx context.Context, userID, roleID, actorID string) (*ent.UserRole, error) {
	client := r.factory.GetClient(ctx, "", "")

	exists, err := client.UserRole.Query().Where(userrole.UserID(userID), userrole.RoleID(roleID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUserRoleExists
	}

	urID := fmt.Sprintf("url_%s", uuid.New().String()[:12])
	builder := client.UserRole.Create().
		SetID(urID).
		SetUserID(userID).
		SetRoleID(roleID)

	if actorID != "" {
		builder.SetAssignedByUserID(actorID)
		builder.SetUpdatedByUserID(actorID)
	}

	return builder.Save(ctx)
}

// RevokeRoleFromUser unbinds a role from a user.
func (r *Repository) RevokeRoleFromUser(ctx context.Context, userID, roleID string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.UserRole.Delete().Where(userrole.UserID(userID), userrole.RoleID(roleID)).Exec(ctx)
	return err
}

// GetUserRolesAndPermissions fetches assigned roles and permissions for a user.
func (r *Repository) GetUserRolesAndPermissions(ctx context.Context, userID string) (roles []string, permissions []string, err error) {
	client := r.factory.GetClient(ctx, "", "")

	userRoles, err := client.UserRole.Query().
		Where(userrole.UserID(userID)).
		WithRole(func(q *ent.RoleQuery) {
			q.WithPermissions()
		}).
		All(ctx)

	if err != nil {
		return nil, nil, err
	}

	rolesMap := make(map[string]bool)
	permsMap := make(map[string]bool)

	for _, ur := range userRoles {
		if ur.Edges.Role != nil {
			// Return the slug (machine-readable) as the role identifier, not the display name
			rolesMap[ur.Edges.Role.Slug] = true
			for _, p := range ur.Edges.Role.Edges.Permissions {
				permsMap[p.Action] = true
			}
		}
	}

	for rName := range rolesMap {
		roles = append(roles, rName)
	}

	for pAction := range permsMap {
		permissions = append(permissions, pAction)
	}

	return roles, permissions, nil
}
