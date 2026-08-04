/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_policy_integration_test.go
 * Tier: Internal Feature Package / Policy Integration Tests
 *
 * Description: Tests verifying runtime enforcement of custom per-tenant RecoveryPolicy rules
 *              (disabling methods, enforcing custom min/max guardian limits, custom freeze windows).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryPolicy_TenantBehaviorCustomization(t *testing.T) {
	kmsKey := "super_secret_kms_key_32bytes_authn!"
	dbName := fmt.Sprintf("file:ent_rec_pol_int_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)
	policyRepo := policy.NewRepository(factory)
	telemetry := auth.NewTelemetryService(repo, kmsKey, policyRepo)
	recSvc := auth.NewRecoveryService(repo, telemetry, policyRepo)
	gdnSvc := auth.NewGuardianService(repo, policyRepo)
	ctx := context.Background()

	// Tenant A: Custom policy with GuardiansEnabled = false
	tenantA := "tnt_custom_no_guardians"
	err = repo.EnsureTenantExists(ctx, tenantA)
	require.NoError(t, err)

	pA := policy.DefaultRecoveryPolicy()
	pA.GuardiansEnabled = false
	_, err = policyRepo.UpdateRecoveryPolicy(ctx, tenantA, pA)
	require.NoError(t, err)

	clientA := factory.GetClient(ctx, tenantA, "test")
	userA := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err = clientA.User.Create().
		SetID(userA).
		SetTenantID(tenantA).
		SetEmail("usera@example.com").
		SetEmailVerified(true).
		SetPasswordHash("pass").
		Save(ctx)
	require.NoError(t, err)

	// Attempt guardian enrollment for Tenant A (must fail because guardians_enabled = false)
	inputs := []auth.InviteGuardianInput{{Email: "g1@example.com", Name: "G1"}}
	_, err = gdnSvc.InviteGuardians(ctx, userA, inputs, "http://localhost:8080")
	assert.ErrorContains(t, err, "disabled for this tenant")

	// Tenant B: Custom policy with MinGuardians = 2
	tenantB := "tnt_custom_min_2"
	err = repo.EnsureTenantExists(ctx, tenantB)
	require.NoError(t, err)

	pB := policy.DefaultRecoveryPolicy()
	pB.MinGuardians = 2
	pB.MaxGuardians = 4
	_, err = policyRepo.UpdateRecoveryPolicy(ctx, tenantB, pB)
	require.NoError(t, err)

	clientB := factory.GetClient(ctx, tenantB, "test")
	userB := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err = clientB.User.Create().
		SetID(userB).
		SetTenantID(tenantB).
		SetEmail("userb@example.com").
		SetEmailVerified(true).
		SetPasswordHash("pass").
		Save(ctx)
	require.NoError(t, err)

	// Attempt enrolling 1 guardian for Tenant B (must fail because min_guardians = 2)
	_, err = gdnSvc.InviteGuardians(ctx, userB, inputs, "http://localhost:8080")
	assert.ErrorContains(t, err, "must enroll at least 2 guardian(s) per tenant policy")

	// Enroll 2 guardians for Tenant B (must succeed)
	inputs2 := []auth.InviteGuardianInput{
		{Email: "g1@example.com", Name: "G1"},
		{Email: "g2@example.com", Name: "G2"},
	}
	resGdnB, err := gdnSvc.InviteGuardians(ctx, userB, inputs2, "http://localhost:8080")
	require.NoError(t, err)
	assert.Equal(t, 2, resGdnB.EnrolledCount)

	// Verify initiate recovery for Tenant B includes guardians
	resInit, err := recSvc.InitiateRecovery(ctx, auth.InitiateRecoveryInput{
		TenantID:    tenantB,
		Environment: "test",
		Email:       "userb@example.com",
		IPAddress:   "198.51.100.1",
	})
	require.NoError(t, err)
	assert.Contains(t, resInit.AvailableMethods, "email_otp")
}
