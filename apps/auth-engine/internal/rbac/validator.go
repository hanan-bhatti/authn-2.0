/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/validator.go
 * Tier: Security & Authorization Layer
 *
 * Description: Syntax and namespace validator for RBAC permissions. Enforces strict
 *              format rules (resource:action or domain:resource:action), action verb constraints, and resource namespaces.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ErrInvalidPermissionFormat = errors.New("permission must follow format 'resource:action' (e.g. 'users:read', 'posts:create')")
	ErrInvalidActionVerb       = errors.New("invalid action verb: must be read, write, create, update, delete, revoke, manage, execute, or *")
	ErrRestrictedPermission    = errors.New("permission assignment is restricted for this role under tenant policy")
)

var permissionRegex = regexp.MustCompile(`^[a-z0-9_]+:([a-z0-9_]+|\*)(:([a-z0-9_]+|\*))?$`)

var validActionVerbs = map[string]bool{
	"read":    true,
	"write":   true,
	"create":  true,
	"update":  true,
	"delete":  true,
	"revoke":  true,
	"manage":  true,
	"execute": true,
	"*":       true,
}

// ValidatePermissionFormat validates a permission string format and action verb.
func ValidatePermissionFormat(perm string) error {
	perm = strings.TrimSpace(perm)
	if perm == "" {
		return errors.New("permission string cannot be empty")
	}
	if perm == "*" {
		return nil
	}

	if !permissionRegex.MatchString(perm) {
		return fmt.Errorf("%w: got '%s'", ErrInvalidPermissionFormat, perm)
	}

	parts := strings.Split(perm, ":")
	actionVerb := parts[len(parts)-1]

	if !validActionVerbs[actionVerb] {
		return fmt.Errorf("%w: '%s'", ErrInvalidActionVerb, actionVerb)
	}

	return nil
}

// ValidatePermissionList validates a slice of permission strings.
func ValidatePermissionList(perms []string) error {
	for _, p := range perms {
		if err := ValidatePermissionFormat(p); err != nil {
			return err
		}
	}
	return nil
}
