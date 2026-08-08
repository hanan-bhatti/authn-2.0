/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/policy.go
 * Tier: Security & Authorization Layer
 *
 * Description: Configurable Role & Permission Policy engine. Enforces restricted permission
 *              mappings per role slug while permitting tenant admin policy overrides.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"fmt"
)

// RolePermissionPolicy defines configurable safety guards for role assignments.
type RolePermissionPolicy struct {
	StrictValidation       bool                `json:"strict_validation"`
	AllowCustomRoles       bool                `json:"allow_custom_roles"`
	RestrictedRoleMappings map[string][]string `json:"restricted_role_mappings"`
}

// DefaultRolePermissionPolicy returns default security guardrails.
func DefaultRolePermissionPolicy() *RolePermissionPolicy {
	return &RolePermissionPolicy{
		StrictValidation: true,
		AllowCustomRoles: true,
		RestrictedRoleMappings: map[string][]string{
			"support_admin": {"system:tenant:delete", "keys:write", "security:write"},
			"member":        {"system:*", "users:delete", "keys:*"},
			"viewer":        {"*:write", "*:delete", "*:create"},
		},
	}
}

// ValidatePermissionsAgainstPolicy checks if any assigned permission in perms matches a restricted pattern for roleSlug.
func ValidatePermissionsAgainstPolicy(roleSlug string, perms []string, policy *RolePermissionPolicy) error {
	if policy == nil {
		policy = DefaultRolePermissionPolicy()
	}

	restrictedList, exists := policy.RestrictedRoleMappings[roleSlug]
	if !exists || len(restrictedList) == 0 {
		return nil
	}

	for _, perm := range perms {
		for _, restricted := range restrictedList {
			if PermissionsOverlap(perm, restricted) {
				return fmt.Errorf("%w: permission '%s' is restricted for role '%s'", ErrRestrictedPermission, perm, roleSlug)
			}
		}
	}

	return nil
}
