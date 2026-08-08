/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/matcher.go
 * Tier: Security & Authorization Layer
 *
 * Description: Single source of truth for permission-string matching. Every wildcard
 *              grant check in the RBAC engine funnels through PermissionMatches so the
 *              matcher cannot drift across call paths (audit H1).
 *
 * Matching rules (pure string comparison, no side effects):
 *   - exact equality, or a granted "*" wildcard, matches anything;
 *   - a granted "prefix:*" matches any permission under that resource namespace;
 *   - a granted "*:action" matches any permission with that action verb.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import "strings"

// PermissionMatches reports whether the granted permission string covers the
// required permission string. granted is the permission a subject holds;
// required is the permission a protected operation demands.
//
// This function intentionally performs no role lookups or administrative
// bypasses: caller-tier bypasses (tenant_admin/super_admin) are decided by the
// caller via IsPrivilegedRole. Keeping the matcher purely syntactic means every
// wildcard decision in the engine is made by exactly one function.
func PermissionMatches(granted, required string) bool {
	if granted == "*" || granted == required {
		return true
	}
	if strings.HasSuffix(granted, ":*") {
		prefix := strings.TrimSuffix(granted, "*")
		return strings.HasPrefix(required, prefix)
	}
	if strings.HasPrefix(granted, "*:") {
		suffix := strings.TrimPrefix(granted, "*")
		return strings.HasSuffix(required, suffix)
	}
	return false
}

// PermissionsOverlap reports whether two permission patterns share at least one
// concrete permission — i.e. whether their permitted sets intersect.
//
// PermissionMatches asks a one-directional question ("does this grant cover this
// concrete requirement?") and is correct for the request gate, where a non-match
// denies. Policy validation asks the opposite-risk question: a non-match ALLOWS
// the assignment, so a matcher gap there fails open. Both operands may also be
// wildcards, which PermissionMatches cannot express — a subject granted "keys:*"
// must still trip a "keys:write" restriction, and "orgs:*" must trip "*:write".
// Overlap is therefore evaluated segment-wise rather than by prefix comparison.
func PermissionsOverlap(a, b string) bool {
	if a == "*" || b == "*" || a == b {
		return true
	}

	aSegs := strings.Split(a, ":")
	bSegs := strings.Split(b, ":")

	for i := 0; ; i++ {
		aDone, bDone := i >= len(aSegs), i >= len(bSegs)
		if aDone || bDone {
			// Both exhausted together means every segment intersected.
			return aDone && bDone
		}

		aSeg, bSeg := aSegs[i], bSegs[i]

		// A trailing "*" absorbs every remaining segment on the other side, so
		// "system:*" intersects "system:tenant:delete".
		if aSeg == "*" && i == len(aSegs)-1 {
			return true
		}
		if bSeg == "*" && i == len(bSegs)-1 {
			return true
		}

		// An interior "*" matches exactly one segment.
		if aSeg != bSeg && aSeg != "*" && bSeg != "*" {
			return false
		}
	}
}

// privilegedAdminRoles are the role slugs that bypass fine-grained permission
// checks entirely. Kept as a single list so RequirePermission, RequireRole,
// Service.HasPermission and the impersonation gate all agree (audit H1).
var privilegedAdminRoles = map[string]struct{}{
	"tenant_admin": {},
	"super_admin":  {},
}

// IsPrivilegedRole reports whether roleSlug is a tenant-level administrative
// role that bypasses fine-grained permission checks.
func IsPrivilegedRole(roleSlug string) bool {
	_, ok := privilegedAdminRoles[roleSlug]
	return ok
}

// HasPrivilegedRole reports whether any of the given roles is a privileged
// administrative role.
func HasPrivilegedRole(roles []string) bool {
	for _, r := range roles {
		if IsPrivilegedRole(r) {
			return true
		}
	}
	return false
}
