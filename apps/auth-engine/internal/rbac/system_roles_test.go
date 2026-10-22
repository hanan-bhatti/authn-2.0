package rbac

import (
	"testing"
)

func BenchmarkEnsureSystemRoles_Existing(b *testing.B) {
	client, ctx := newClaimTestEnv(b, "system_roles_bench_existing")
	defer client.Close()
	tenantID := "tnt_00000000000000000000000000000001"

	// Provision once first so that benchmark mostly tests the "already provisioned" case
	// which is common in idempotent operations.
	_, err := EnsureSystemRoles(ctx, client, tenantID)
	if err != nil {
		b.Fatalf("failed to ensure roles initially: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EnsureSystemRoles(ctx, client, tenantID)
		if err != nil {
			b.Fatalf("failed to ensure roles: %v", err)
		}
	}
}
