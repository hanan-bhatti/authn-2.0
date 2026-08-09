/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/matcher.go
 * Tier: Security & Authorization Layer
 *
 * Permission-string matching — the single source of truth for every wildcard
 * decision in the RBAC engine.
 *
 * Permissions are colon-delimited strings, either "resource:action" or
 * "domain:resource:action", where any segment may be "*". Both matchers here are
 * pure string comparison: no role lookups, no database access, no administrative
 * bypasses. Every wildcard grant check funnels through this file so the rules
 * cannot drift between the request gate and policy validation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import "strings"

// PermissionMatches reports whether the granted permission covers the required
// one: granted is a permission the subject holds, required is the concrete
// permission a protected operation demands.
//
// A granted "*" matches anything, a granted "prefix:*" matches any permission in
// that resource namespace, and a granted "*:action" matches any permission with
// that action verb. Everything else must be equal.
//
// The match is one-directional and purely syntactic. Caller-tier bypasses
// (tenant_admin, super_admin) are decided separately via IsPrivilegedRole, which
// keeps the wildcard rules in one function and the privilege rules in another.
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
// concrete permission — whether the sets they permit intersect.
//
// This is deliberately a second function rather than a reuse of
// PermissionMatches, because the two answer questions of opposite risk and
// merging them fails open:
//
//   - PermissionMatches is asked at the request gate, where a non-match DENIES.
//     Its operands are a grant and a concrete requirement, and its bias toward
//     "no" is safe.
//   - PermissionsOverlap is asked during policy validation, where a non-match
//     ALLOWS the assignment. Both operands may be wildcards, a case
//     PermissionMatches cannot express at all: a subject granted "keys:*" must
//     still trip a "keys:write" restriction, and "orgs:*" must trip "*:write".
//     A gap here hands out the very permission the policy forbids.
//
// Intersection is therefore evaluated segment by segment rather than by prefix
// comparison.
func PermissionsOverlap(a, b string) bool {
	if a == "*" || b == "*" || a == b {
		return true
	}

	aSegs := strings.Split(a, ":")
	bSegs := strings.Split(b, ":")

	for i := 0; ; i++ {
		aDone, bDone := i >= len(aSegs), i >= len(bSegs)
		if aDone || bDone {
			// Both exhausted together means every segment intersected. One
			// exhausted alone means the patterns have different depth and no
			// trailing wildcard bridged them.
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
// checks entirely. One list, so RequirePermission, RequireRole,
// Service.HasPermission and the impersonation gate cannot disagree about who is
// an administrator.
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

// HasPrivilegedRole reports whether any slug in roles is a privileged
// administrative role.
func HasPrivilegedRole(roles []string) bool {
	for _, r := range roles {
		if IsPrivilegedRole(r) {
			return true
		}
	}
	return false
}
