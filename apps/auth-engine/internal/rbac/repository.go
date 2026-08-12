/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/repository.go
 * Tier: Database Persistence Layer
 *
 * Persistence for roles, their permissions, and user-role bindings.
 *
 * Queries run through the client factory and therefore inherit the request's
 * privacy context: the ORM interceptor requires an active tenant for every role,
 * permission and user-role query and scopes it accordingly, so tenant isolation
 * is enforced below this layer rather than by predicates written here.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"
	"errors"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/permission"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

var (
	// ErrRoleNotFound reports that no role matches the given ID or slug within
	// the requesting tenant.
	ErrRoleNotFound = errors.New("role not found")
	// ErrRoleExists reports a name or slug collision within the tenant.
	ErrRoleExists = errors.New("role with this name or slug already exists in tenant")
	// ErrSystemRoleDelete reports an attempt to delete a built-in role.
	ErrSystemRoleDelete = errors.New("built-in system roles cannot be deleted")
	// ErrUserRoleExists reports that the user already holds the role.
	ErrUserRoleExists = errors.New("user already possesses this role")
)

// Repository reads and writes RBAC entities.
type Repository struct {
	// factory produces the ORM client for the request's tenant and environment.
	factory *clientfactory.ClientFactory
}

// NewRepository returns an RBAC repository backed by the given client factory.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// CreateRole inserts a role, deriving name from slug or slug from name when
// either is empty, and returns ErrRoleExists if the tenant already has a role
// with that name or slug. isSystem marks a built-in role, which DeleteRole then
// refuses to remove.
func (r *Repository) CreateRole(ctx context.Context, tenantID, name, slug, description string, isSystem bool, actorID string) (*ent.Role, error) {
	client := r.factory.GetClient(ctx, tenantID, "")

	roleName := name
	if roleName == "" {
		roleName = slug
	}
	roleSlug := slug
	if roleSlug == "" {
		roleSlug = strings.ToLower(strings.ReplaceAll(roleName, " ", "_"))
	}

	nameExists, err := client.Role.Query().Where(role.TenantID(tenantID), role.Name(roleName)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if nameExists {
		return nil, ErrRoleExists
	}

	slugExists, err := client.Role.Query().Where(role.TenantID(tenantID), role.Slug(roleSlug)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if slugExists {
		return nil, ErrRoleExists
	}

	roleID := idgen.New("rol")
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

// GetRoleByID returns a role with its permissions loaded, or ErrRoleNotFound.
// The tenant predicate is supplied by the privacy interceptor, so a role ID from
// another tenant does not resolve.
func (r *Repository) GetRoleByID(ctx context.Context, roleID string) (*ent.Role, error) {
	client := r.factory.GetClient(ctx, "", "")
	roleObj, err := client.Role.Query().Where(role.ID(roleID)).WithPermissions().Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrRoleNotFound
	}
	return roleObj, err
}

// GetRoleBySlug returns the role with an exact slug match in the tenant, with
// its permissions loaded, or ErrRoleNotFound.
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

// ListRoles returns every role in the tenant with its permissions loaded.
func (r *Repository) ListRoles(ctx context.Context, tenantID string) ([]*ent.Role, error) {
	client := r.factory.GetClient(ctx, tenantID, "")
	return client.Role.Query().Where(role.TenantID(tenantID)).WithPermissions().All(ctx)
}

// UpdateRole renames a role and, when the arguments are non-empty, updates its
// description and records the actor. It returns the updated role or the ORM
// error.
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

// DeleteRole removes a role along with its permissions and user bindings,
// returning ErrSystemRoleDelete for a built-in role and ErrRoleNotFound for an
// unknown one. Leaving the bindings behind would strand rows pointing at a role
// that no longer exists, so they go first.
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

// SetRolePermissions replaces a role's entire permission set: the existing rows
// are deleted, then perms inserted. Replacing rather than merging is what makes
// a permission removal possible at all — a caller sends the set it wants, not a
// delta. It returns the first write error.
func (r *Repository) SetRolePermissions(ctx context.Context, roleID string, perms []string, actorID string) error {
	client := r.factory.GetClient(ctx, "", "")

	_, err := client.Permission.Delete().Where(permission.RoleID(roleID)).Exec(ctx)
	if err != nil {
		return err
	}

	for _, p := range perms {
		prmID := idgen.New("prm")
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

// AssignRoleToUser binds a role to a user, returning ErrUserRoleExists when the
// binding already exists and the new binding otherwise.
func (r *Repository) AssignRoleToUser(ctx context.Context, userID, roleID, actorID string) (*ent.UserRole, error) {
	client := r.factory.GetClient(ctx, "", "")

	exists, err := client.UserRole.Query().Where(userrole.UserID(userID), userrole.RoleID(roleID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrUserRoleExists
	}

	urID := idgen.New("url")
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

// RevokeRoleFromUser removes the binding between a user and a role. Removing a
// binding that does not exist is not an error.
func (r *Repository) RevokeRoleFromUser(ctx context.Context, userID, roleID string) error {
	client := r.factory.GetClient(ctx, "", "")
	_, err := client.UserRole.Delete().Where(userrole.UserID(userID), userrole.RoleID(roleID)).Exec(ctx)
	return err
}

// GetUserRolesAndPermissions returns the user's role slugs and the deduplicated
// union of the permissions those roles carry, or the query error. Both slices
// are nil for a user with no roles. Order is unspecified, as both are consumed
// as sets.
//
// Roles are reported by slug rather than display name: the slug is what
// IsPrivilegedRole and every policy lookup match on, and a display name is
// editable text.
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
