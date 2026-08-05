/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/service.go
 * Tier: Security & Authorization Service Layer
 *
 * Description: RBAC service orchestrating role management, permission validation,
 *              policy checks, and immutable security audit trail logging.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

type Service struct {
	repo   *Repository
	audit  *AuditLogger
	cfg    *config.EnvConfig
	policy *RolePermissionPolicy
}

func NewService(repo *Repository, audit *AuditLogger, cfg *config.EnvConfig) *Service {
	return &Service{
		repo:   repo,
		audit:  audit,
		cfg:    cfg,
		policy: DefaultRolePermissionPolicy(),
	}
}

// CreateRole creates a new role with validation, policy checks, permission assignment, and audit logging.
func (s *Service) CreateRole(ctx context.Context, tenantID, name, slug, description string, perms []string, actorID, ip, ua string) (*ent.Role, error) {
	if err := ValidatePermissionList(perms); err != nil {
		return nil, err
	}

	roleSlug := slug
	if roleSlug == "" {
		roleSlug = name
	}

	if err := ValidatePermissionsAgainstPolicy(roleSlug, perms, s.policy); err != nil {
		return nil, err
	}

	roleObj, err := s.repo.CreateRole(ctx, tenantID, name, roleSlug, description, false, actorID)
	if err != nil {
		return nil, err
	}

	if len(perms) > 0 {
		if err := s.repo.SetRolePermissions(ctx, roleObj.ID, perms, actorID); err != nil {
			return nil, err
		}
	}

	_ = s.audit.LogRBACEvent(ctx, tenantID, "admin", actorID, "rbac.role.created", "role", roleObj.ID, map[string]interface{}{
		"role_name":   name,
		"role_slug":   roleSlug,
		"permissions": perms,
	}, ip, ua)

	return roleObj, nil
}

// UpdateRolePermissions updates permissions for a role with policy checks and audit logging.
func (s *Service) UpdateRolePermissions(ctx context.Context, tenantID, roleID string, perms []string, actorID, ip, ua string) error {
	if err := ValidatePermissionList(perms); err != nil {
		return err
	}

	roleObj, err := s.repo.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	if err := ValidatePermissionsAgainstPolicy(roleObj.Slug, perms, s.policy); err != nil {
		return err
	}

	oldPerms := make([]string, len(roleObj.Edges.Permissions))
	for i, p := range roleObj.Edges.Permissions {
		oldPerms[i] = p.Action
	}

	if err := s.repo.SetRolePermissions(ctx, roleID, perms, actorID); err != nil {
		return err
	}

	_ = s.audit.LogRBACEvent(ctx, tenantID, "admin", actorID, "rbac.role.permissions_updated", "role", roleID, map[string]interface{}{
		"role_name":       roleObj.Name,
		"role_slug":       roleObj.Slug,
		"old_permissions": oldPerms,
		"new_permissions": perms,
	}, ip, ua)

	return nil
}

// AssignUserRole assigns a role to a target user and records audit trail.
func (s *Service) AssignUserRole(ctx context.Context, tenantID, targetUserID, roleSlug, actorID, ip, ua string) error {
	roleObj, err := s.repo.GetRoleBySlug(ctx, tenantID, roleSlug)
	if err != nil {
		return err
	}

	_, err = s.repo.AssignRoleToUser(ctx, targetUserID, roleObj.ID, actorID)
	if err != nil {
		return err
	}

	_ = s.audit.LogRBACEvent(ctx, tenantID, "admin", actorID, "rbac.user_role.assigned", "user", targetUserID, map[string]interface{}{
		"target_user_id":   targetUserID,
		"assigned_role":    roleObj.Slug,
		"role_name":        roleObj.Name,
		"role_id":          roleObj.ID,
		"assigned_by_user": actorID,
	}, ip, ua)

	return nil
}

// RevokeUserRole revokes a role from a user and records audit trail.
func (s *Service) RevokeUserRole(ctx context.Context, tenantID, targetUserID, roleSlug, actorID, ip, ua string) error {
	roleObj, err := s.repo.GetRoleBySlug(ctx, tenantID, roleSlug)
	if err != nil {
		return err
	}

	if err := s.repo.RevokeRoleFromUser(ctx, targetUserID, roleObj.ID); err != nil {
		return err
	}

	_ = s.audit.LogRBACEvent(ctx, tenantID, "admin", actorID, "rbac.user_role.revoked", "user", targetUserID, map[string]interface{}{
		"target_user_id":  targetUserID,
		"revoked_role":    roleObj.Slug,
		"role_name":       roleObj.Name,
		"role_id":         roleObj.ID,
		"revoked_by_user": actorID,
	}, ip, ua)

	return nil
}

// ListRoles returns all roles for a tenant.
func (s *Service) ListRoles(ctx context.Context, tenantID string) ([]*ent.Role, error) {
	return s.repo.ListRoles(ctx, tenantID)
}

// GetUserRBAC returns accumulated roles and permissions for a user.
func (s *Service) GetUserRBAC(ctx context.Context, userID string) (roles []string, permissions []string, err error) {
	return s.repo.GetUserRolesAndPermissions(ctx, userID)
}
