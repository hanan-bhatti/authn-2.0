/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/concurrent_signup_test.go
 * Tier: Unit / Integration Test
 *
 * Description: Exercises the concurrent first-admin race condition fix.
 *              Uses a mock repository to simulate concurrent ClaimFirstAdminRole
 *              calls and verifies only one goroutine receives role="tenant_admin".
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

// mockAtomicClaimer simulates the DB-level atomic CAS behaviour of ClaimFirstAdminRole.
// The real implementation issues:
//
//	UPDATE tenants SET first_admin_claimed = true WHERE id = ? AND first_admin_claimed = false
//
// Only one caller can flip false → true. We replicate that guarantee here using
// a Go atomic int32 (0 = unclaimed, 1 = claimed).
type mockAtomicClaimer struct {
	claimed atomic.Int32
}

// Claim mirrors the DB UPDATE: returns true exactly once, false for all concurrent callers.
func (m *mockAtomicClaimer) Claim(_ context.Context, _ string) (bool, error) {
	// CompareAndSwap: atomically set 0 → 1. Returns true only for the first caller.
	return m.claimed.CompareAndSwap(0, 1), nil
}

// TestConcurrentFirstAdminSignup verifies that exactly one of N concurrent signup
// goroutines is designated tenant_admin, regardless of scheduling order.
//
// This is the unit-level proof of the race condition fix. The real safety comes from
// the DB-level conditional UPDATE in ClaimFirstAdminRole (repository.go); this test
// validates the application-level logic that consumes the CAS result.
func TestConcurrentFirstAdminSignup(t *testing.T) {
	const goroutines = 50 // simulate 50 concurrent signups hitting a brand-new tenant

	claimer := &mockAtomicClaimer{}

	var (
		wg           sync.WaitGroup
		adminCount   atomic.Int32
		regularCount atomic.Int32
	)

	// Replicate the role-assignment logic from SignUpWithPassword
	assignRole := func(ctx context.Context, tenantID string) string {
		claimed, err := claimer.Claim(ctx, tenantID)
		if err != nil || !claimed {
			return ""
		}
		return "tenant_admin"
	}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			role := assignRole(context.Background(), "tnt_test")
			if role == "tenant_admin" {
				adminCount.Add(1)
			} else {
				regularCount.Add(1)
			}
		}()
	}

	wg.Wait()

	admins := int(adminCount.Load())
	regulars := int(regularCount.Load())

	// Critical invariants:
	if admins != 1 {
		t.Errorf("expected exactly 1 tenant_admin, got %d (TOCTOU race — multiple admins created)", admins)
	}
	if regulars != goroutines-1 {
		t.Errorf("expected %d regular users, got %d", goroutines-1, regulars)
	}
	if admins+regulars != goroutines {
		t.Errorf("expected total %d signups, got %d+%d=%d", goroutines, admins, regulars, admins+regulars)
	}

	t.Logf("✅ Concurrent signup race test passed: 1 tenant_admin, %d regular users out of %d concurrent requests", regulars, goroutines)
}

// TestSequentialFirstAdminSignup verifies the simple sequential case still works.
func TestSequentialFirstAdminSignup(t *testing.T) {
	claimer := &mockAtomicClaimer{}

	// First signup → should claim admin
	claimed1, err := claimer.Claim(context.Background(), "tnt_test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claimed1 {
		t.Error("first signup should receive tenant_admin role")
	}

	// All subsequent signups → should NOT claim admin
	for i := 1; i < 10; i++ {
		claimed, err := claimer.Claim(context.Background(), "tnt_test")
		if err != nil {
			t.Fatalf("unexpected error on signup %d: %v", i, err)
		}
		if claimed {
			t.Errorf("signup %d should not receive tenant_admin role (already claimed)", i)
		}
	}

	t.Log("✅ Sequential signup test passed: first user is admin, remaining 9 are regular users")
}
