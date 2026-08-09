/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/policy.go
 * Tier: Security & Authorization Layer
 *
 * Tenant-configurable guardrails on which permissions a role may hold.
 *
 * Role membership is one control; what a role is allowed to contain is another.
 * These mappings stop a lower-tier role from being quietly upgraded into an
 * administrative one by permission assignment — a support role granted
 * "system:*" is an administrator whatever its slug says.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"fmt"
)

// RolePermissionPolicy holds the assignment guardrails for one tenant.
type RolePermissionPolicy struct {
	// StrictValidation reserves the setting for tenants that opt into stricter
	// assignment rules than the restricted mappings alone provide.
	StrictValidation bool `json:"strict_validation"`
	// AllowCustomRoles permits roles beyond the built-in set.
	AllowCustomRoles bool `json:"allow_custom_roles"`
	// RestrictedRoleMappings lists, per role slug, the permission patterns that
	// role may not hold. A pattern matches by intersection, not equality, so a
	// wildcard grant cannot slip past a narrower restriction.
	RestrictedRoleMappings map[string][]string `json:"restricted_role_mappings"`
}

// DefaultRolePermissionPolicy returns the guardrails applied when a tenant has
// configured none: support roles are kept out of tenant destruction, key and
// security writes; members out of system and key administration and user
// deletion; viewers out of every mutating verb.
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

// ValidatePermissionsAgainstPolicy reports whether roleSlug may hold every
// permission in perms, returning ErrRestrictedPermission (wrapped with the
// offending permission and role) for the first one it may not. A nil policy is
// evaluated against DefaultRolePermissionPolicy, and a role with no restrictions
// listed passes.
//
// Comparison uses PermissionsOverlap rather than PermissionMatches because both
// sides may be wildcards, and because a non-match here permits the assignment: a
// matcher that missed an intersection would hand out exactly the permission the
// restriction names.
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
