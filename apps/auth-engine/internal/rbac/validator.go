/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/validator.go
 * Tier: Security & Authorization Layer
 *
 * Syntax validation for permission strings.
 *
 * A permission is "resource:action" or "domain:resource:action", lowercase, with
 * "*" permitted in any segment. Constraining the grammar and the action verb at
 * assignment time is what makes the matcher's rules meaningful: a typo that
 * would otherwise become a permanently unmatched grant is rejected where it is
 * written rather than silently failing at every check.
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
	// ErrInvalidPermissionFormat reports a permission string that does not match
	// the resource:action grammar.
	ErrInvalidPermissionFormat = errors.New("permission must follow format 'resource:action' (e.g. 'users:read', 'posts:create')")
	// ErrInvalidActionVerb reports a well-formed permission whose trailing
	// segment is not a recognised verb.
	ErrInvalidActionVerb = errors.New("invalid action verb: must be read, write, create, update, delete, revoke, manage, execute, or *")
	// ErrRestrictedPermission reports a permission that tenant policy forbids the
	// target role from holding.
	ErrRestrictedPermission = errors.New("permission assignment is restricted for this role under tenant policy")
)

// permissionRegex matches two- or three-segment permissions of lowercase
// alphanumerics and underscores, where the second and third segments may be "*".
// The first segment may not be a bare wildcard; a whole-permission "*" is
// handled ahead of the pattern.
var permissionRegex = regexp.MustCompile(`^[a-z0-9_]+:([a-z0-9_]+|\*)(:([a-z0-9_]+|\*))?$`)

// validActionVerbs is the closed set of action verbs a permission may end in.
// Keeping it closed means a new verb is a deliberate addition rather than
// whatever an operator happened to type.
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

// ValidatePermissionFormat checks one permission string's grammar and action
// verb. It returns ErrInvalidPermissionFormat (wrapped with the input) for a
// malformed string, ErrInvalidActionVerb (wrapped with the verb) for an
// unrecognised trailing segment, and a plain error for an empty string. The
// whole-permission wildcard "*" is valid.
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

// ValidatePermissionList checks every permission in perms and returns the first
// failure, so a rejected assignment names the specific permission at fault. An
// empty slice is valid.
func ValidatePermissionList(perms []string) error {
	for _, p := range perms {
		if err := ValidatePermissionFormat(p); err != nil {
			return err
		}
	}
	return nil
}
