/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/matcher_test.go
 * Tier: Security & Authorization Layer / Tests
 *
 * Description: Tests for the permission matcher: wildcard grant coverage,
 * pattern intersection for policy validation, and the privileged-role bypass.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import "testing"

func TestPermissionMatches(t *testing.T) {
	cases := []struct {
		name     string
		granted  string
		required string
		want     bool
	}{
		{"exact match", "users:read", "users:read", true},
		{"global wildcard grants anything", "*", "billing:delete", true},
		{"resource wildcard covers its namespace", "users:*", "users:read", true},
		{"action wildcard covers that verb", "*:read", "users:read", true},
		{"unrelated permission denied", "billing:read", "billing:write", false},
		{"different resource denied", "users:read", "billing:read", false},

		// A wildcard grant covers its own namespace and nothing else. Comparing
		// these literals against the HELD permission instead of the required one
		// turns either into a master key for every check in the engine.
		{"users:* does not grant billing:delete", "users:*", "billing:delete", false},
		{"users:* does not grant apikeys:manage", "users:*", "apikeys:manage", false},
		{"impersonate:* does not grant billing:delete", "impersonate:*", "billing:delete", false},

		// The impersonation permission is "users:impersonate", so an
		// "impersonate:*" grant does not reach it.
		{"impersonate:* does not cover users:impersonate", "impersonate:*", "users:impersonate", false},
		{"users:* does cover users:impersonate", "users:*", "users:impersonate", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PermissionMatches(tc.granted, tc.required); got != tc.want {
				t.Errorf("PermissionMatches(%q, %q) = %v, want %v",
					tc.granted, tc.required, got, tc.want)
			}
		})
	}
}

func TestPermissionsOverlap(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"identical", "users:delete", "users:delete", true},
		{"global wildcard on either side", "*", "keys:write", true},
		{"wildcard grant trips concrete restriction", "keys:*", "keys:write", true},
		{"deep restriction under wildcard grant", "system:tenant:delete", "system:*", true},
		{"concrete grant trips action restriction", "orgs:write", "*:write", true},
		{"unrelated action does not trip", "orgs:read", "*:write", false},
		{"unrelated resource does not trip", "users:read", "keys:write", false},
		{"differing depth does not trip", "users:read", "users:read:extra", false},

		// Both operands may be wildcards, which prefix comparison cannot express:
		// a viewer granted "orgs:*" must still trip the "*:write" restriction,
		// because "orgs:*" contains "orgs:write".
		{"wildcard grant vs wildcard restriction", "orgs:*", "*:write", true},
		{"member granted keys:* trips keys:write restriction", "keys:*", "keys:write", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PermissionsOverlap(tc.a, tc.b); got != tc.want {
				t.Errorf("PermissionsOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			// Overlap is a symmetric relation; asymmetry would make policy
			// enforcement depend on argument order.
			if got := PermissionsOverlap(tc.b, tc.a); got != tc.want {
				t.Errorf("PermissionsOverlap(%q, %q) [reversed] = %v, want %v",
					tc.b, tc.a, got, tc.want)
			}
		})
	}
}

func TestPrivilegedRoles(t *testing.T) {
	for _, r := range []string{"tenant_admin", "super_admin"} {
		if !IsPrivilegedRole(r) {
			t.Errorf("IsPrivilegedRole(%q) = false, want true", r)
		}
	}

	// org_admin is scoped to a single organization and support_admin is
	// deliberately restricted by DefaultRolePermissionPolicy; neither may
	// bypass tenant-wide permission checks. "admin" is not a seeded slug and
	// role creation has no reserved-slug guard, so honouring it would let a
	// tenant mint a bypass role.
	for _, r := range []string{"org_admin", "support_admin", "admin", "editor", "viewer", ""} {
		if IsPrivilegedRole(r) {
			t.Errorf("IsPrivilegedRole(%q) = true, want false", r)
		}
	}

	if !HasPrivilegedRole([]string{"viewer", "tenant_admin"}) {
		t.Error("HasPrivilegedRole should find tenant_admin among multiple roles")
	}
	if HasPrivilegedRole([]string{"viewer", "editor"}) {
		t.Error("HasPrivilegedRole should not match non-privileged roles")
	}
}

// The restricted mappings in DefaultRolePermissionPolicy are the real policy
// this engine ships with; assert against them directly.
func TestValidatePermissionsAgainstPolicy(t *testing.T) {
	cases := []struct {
		name      string
		roleSlug  string
		perms     []string
		wantError bool
	}{
		{"member cannot take system:*", "member", []string{"system:*"}, true},
		{"member cannot take users:delete", "member", []string{"users:delete"}, true},
		{"member cannot take keys:write via keys:*", "member", []string{"keys:*"}, true},
		{"member cannot take system:tenant:delete", "member", []string{"system:tenant:delete"}, true},
		{"member may take benign perms", "member", []string{"orgs:read", "content:write"}, false},

		{"viewer cannot take orgs:write", "viewer", []string{"orgs:write"}, true},
		{"viewer cannot escalate via orgs:*", "viewer", []string{"orgs:*"}, true},
		{"viewer may read", "viewer", []string{"orgs:read", "members:read"}, false},

		{"support_admin cannot take keys:write", "support_admin", []string{"keys:write"}, true},
		{"support_admin cannot take security:write", "support_admin", []string{"security:write"}, true},

		{"unrestricted role slug is unaffected", "editor", []string{"system:*"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePermissionsAgainstPolicy(tc.roleSlug, tc.perms, nil)
			if tc.wantError && err == nil {
				t.Errorf("expected restriction error for role %q perms %v, got nil",
					tc.roleSlug, tc.perms)
			}
			if !tc.wantError && err != nil {
				t.Errorf("unexpected error for role %q perms %v: %v",
					tc.roleSlug, tc.perms, err)
			}
		})
	}
}
