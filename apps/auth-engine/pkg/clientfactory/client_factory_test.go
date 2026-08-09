/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/clientfactory/client_factory_test.go
 * Tier: Shared Package / Tests
 *
 * Description: Pins what GetClient's tenant and environment arguments actually
 *              do, so a reader does not mistake them for the mechanism that
 *              keeps one tenant's rows away from another.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package clientfactory

import (
	"context"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// newTestFactory opens a factory against a private in-memory database.
func newTestFactory(t *testing.T, name string) *ClientFactory {
	t.Helper()
	f, err := NewClientFactory("sqlite3", "file:"+name+"?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("NewClientFactory: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestGetClientReturnsTheDefaultForEveryTenant records that the tenant and
// environment arguments select nothing today.
//
// Nothing registers a per-tenant pool, so every caller shares one client. This
// matters because the arguments read like an isolation boundary and are not one:
// isolation is enforced by the privacy interceptors, which narrow each query by
// the tenant and environment on the request context. A future change that makes
// these arguments live should fail here first.
func TestGetClientReturnsTheDefaultForEveryTenant(t *testing.T) {
	f := newTestFactory(t, "cf_default_test")
	ctx := context.Background()

	baseline := f.GetClient(ctx, "", "")
	if baseline == nil {
		t.Fatal("GetClient returned nil; callers do not nil-check it")
	}

	cases := []struct{ tenant, env string }{
		{"tnt_a", "test"},
		{"tnt_a", "live"},
		{"tnt_b", "test"},
		{"tnt_unknown", "anything"},
		{"", "live"},
	}
	for _, c := range cases {
		if got := f.GetClient(ctx, c.tenant, c.env); got != baseline {
			t.Errorf("GetClient(%q, %q) returned a different client; a dedicated "+
				"pool is now being selected, so every hardcoded environment "+
				"argument in the codebase has become significant", c.tenant, c.env)
		}
	}
}

// The policy repository passes a fixed "test" environment. That is only safe
// while the argument selects nothing, which is what this asserts.
func TestGetClientIgnoresEnvironmentForPoolSelection(t *testing.T) {
	f := newTestFactory(t, "cf_env_test")
	ctx := context.Background()

	if f.GetClient(ctx, "tnt_x", "test") != f.GetClient(ctx, "tnt_x", "live") {
		t.Error("environment now selects a distinct pool: policyPoolEnvironment's " +
			"hardcoded \"test\" would send policy reads to the wrong database")
	}
}
