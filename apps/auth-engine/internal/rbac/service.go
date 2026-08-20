/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/service.go
 * Tier: Security & Authorization Service Layer
 *
 * RBAC orchestration: role lifecycle, permission validation against tenant
 * policy, user-role assignment, and the audit trail that records who changed
 * whose authority.
 *
 * Every mutation here is written to the audit log. The log write is best-effort
 * and never fails the operation — an authorization change that succeeded must
 * not be reported as failed because its record could not be stored.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

// WebhookDispatcher publishes authorization changes to tenant webhooks.
type WebhookDispatcher interface {
	// Dispatch queues an event for delivery. It must not block the caller.
	//
	// environment is the environment the event originated in, and decides which
	// of the tenant's endpoints receive it.
	Dispatch(tenantID, environment, eventType string, data map[string]interface{})
}

// Service applies RBAC business rules on top of the repository.
type Service struct {
	// repo is the persistence layer for roles, permissions and assignments.
	repo *Repository
	// audit records every role and permission change.
	audit *AuditLogger
	// cfg supplies runtime settings, including the secret used to verify a
	// caller's token when no identity is present on the request locals.
	cfg *config.Config
	// policy holds the restricted role-to-permission mappings enforced on every
	// assignment.
	policy *RolePermissionPolicy
	// webhooks publishes role assignments. May be nil, which disables emission.
	webhooks WebhookDispatcher
}

// NewService constructs an RBAC service using the default role-permission
// policy guardrails.
func NewService(repo *Repository, audit *AuditLogger, cfg *config.Config) *Service {
	return &Service{
		repo:   repo,
		audit:  audit,
		cfg:    cfg,
		policy: DefaultRolePermissionPolicy(),
	}
}

// WithWebhooks attaches the dispatcher that publishes authorization changes, and
// returns the service for chaining.
//
// A separate method rather than a constructor parameter, so the tests that build
// this service need no webhook engine standing behind them.
func (s *Service) WithWebhooks(d WebhookDispatcher) *Service {
	s.webhooks = d
	return s
}

// emit queues a webhook event, doing nothing when no dispatcher is attached.
//
// The guard lives here rather than at each call site because emission is a
// notification: no caller branches on it, and an authorization change is not
// undone because its announcement had nowhere to go.
func (s *Service) emit(tenantID, environment, eventType string, data map[string]interface{}) {
	if s.webhooks == nil {
		return
	}
	s.webhooks.Dispatch(tenantID, environment, eventType, data)
}

// CreateRole validates perms, checks them against the tenant's restricted
// mappings, creates the role, and attaches its permissions.
//
// slug defaults to name when empty. It returns ErrInvalidPermissionFormat or
// ErrInvalidActionVerb for a malformed permission, ErrRestrictedPermission when
// the role may not hold one of them, ErrRoleExists when the name or slug is
// taken, and the repository's error otherwise. Validation runs before any write,
// so a rejected request leaves no partial role behind.
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

// UpdateRolePermissions replaces a role's permission set after validating the
// new set against format rules and the tenant's restricted mappings.
//
// The policy check uses the stored role's slug, not a caller-supplied one, so a
// request cannot dodge a restriction by naming a different role. It returns the
// same validation sentinels as CreateRole, ErrRoleNotFound for an unknown role,
// and the repository's error otherwise. The audit entry carries both the old and
// the new permission sets.
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

// AssignUserRole grants the role named by roleSlug, within tenantID, to
// targetUserID. It returns ErrRoleNotFound when the slug names no role in that
// tenant, ErrUserNotFound when the target user does not belong to the tenant,
// and ErrUserRoleExists when the user already holds it.
func (s *Service) AssignUserRole(ctx context.Context, tenantID, targetUserID, roleSlug, actorID, ip, ua string) error {
	roleObj, err := s.repo.GetRoleBySlug(ctx, tenantID, roleSlug)
	if err != nil {
		return err
	}

	// The target's tenant is verified for the same reason the revoke path verifies
	// it, and the privacy interceptor cannot stand in for the check: the assignment
	// is an insert, and a mutation's scope predicates only constrain updates and
	// deletes. Without this, a role belonging to this tenant could be attached to
	// another tenant's user, who would then carry its permissions.
	targetUser, err := s.repo.GetTenantUser(ctx, tenantID, targetUserID)
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

	s.emit(tenantID, string(targetUser.Environment), "rbac.role.assigned", map[string]interface{}{
		"user_id":   targetUserID,
		"role_id":   roleObj.ID,
		"role_slug": roleObj.Slug,
		"role_name": roleObj.Name,
		"actor_id":  actorID,
	})

	return nil
}

// RevokeUserRole removes the role named by roleSlug from targetUserID. It
// returns ErrRoleNotFound when the slug names no role in the tenant,
// ErrUserNotFound when the target user does not belong to the tenant, and no
// error when the user simply did not hold the role.
func (s *Service) RevokeUserRole(ctx context.Context, tenantID, targetUserID, roleSlug, actorID, ip, ua string) error {
	// The role slug is resolved first: if the slug is unknown in this tenant
	// the rest of the operation is moot regardless of whether the user is valid.
	roleObj, err := s.repo.GetRoleBySlug(ctx, tenantID, roleSlug)
	if err != nil {
		return err
	}

	// Verify the target user exists in this tenant before performing the delete.
	// Without this check a caller could silently revoke a role from a user in
	// another tenant (the UserRole.Delete predicate filters only by userID and
	// roleID, not by the user's tenant).
	targetUser, err := s.repo.GetTenantUser(ctx, tenantID, targetUserID)
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

	s.emit(tenantID, string(targetUser.Environment), "rbac.role.revoked", map[string]interface{}{
		"user_id":   targetUserID,
		"role_id":   roleObj.ID,
		"role_slug": roleObj.Slug,
		"role_name": roleObj.Name,
		"actor_id":  actorID,
	})

	return nil
}

// ListRoles returns every role defined in a tenant, each with its permissions
// loaded.
func (s *Service) ListRoles(ctx context.Context, tenantID string) ([]*ent.Role, error) {
	return s.repo.ListRoles(ctx, tenantID)
}

// GetUserRBAC returns the role slugs and the union of permissions a user holds
// across all of them, or the repository's error.
func (s *Service) GetUserRBAC(ctx context.Context, userID string) (roles []string, permissions []string, err error) {
	return s.repo.GetUserRolesAndPermissions(ctx, userID)
}

// HasPermission reports whether a user holds requiredPerm, either through a
// privileged administrative role or through a granted permission that covers it.
// It returns the repository's error when the roles cannot be read, and false —
// never a default grant — alongside it.
//
// Matching is delegated to PermissionMatches with the held permission as the
// grant and requiredPerm as the requirement. The direction matters: comparing a
// literal pattern against the held permission instead would make any wildcard
// grant a universal one.
func (s *Service) HasPermission(ctx context.Context, userID string, requiredPerm string) (bool, error) {
	roles, perms, err := s.repo.GetUserRolesAndPermissions(ctx, userID)
	if err != nil {
		return false, err
	}
	if HasPrivilegedRole(roles) {
		return true, nil
	}
	for _, p := range perms {
		if PermissionMatches(p, requiredPerm) {
			return true, nil
		}
	}
	return false, nil
}
