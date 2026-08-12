/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/recovery_policy_test.go
 * Tier: Domain Model & Integration Test Layer
 *
 * Description: Unit and integration tests for tenant RecoveryPolicy validation,
 *              all 9 strict bounds rules, default-fallback behavior, and HTTP API endpoints.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRecoveryPolicy_All9Rules(t *testing.T) {
	// Baseline valid policy
	valid := policy.DefaultRecoveryPolicy()
	require.NoError(t, policy.ValidateRecoveryPolicy(valid), "Default policy MUST be valid")

	// Rule 1: freeze_window_hours (24 - 168)
	p1 := valid
	p1.FreezeWindowHours = 12
	err := policy.ValidateRecoveryPolicy(p1)
	assert.ErrorContains(t, err, "freeze_window_hours must be between 24 and 168")

	// Rule 2: claim_token_ttl_minutes (5 - 60)
	p2 := valid
	p2.ClaimTokenTTLMinutes = 2
	err = policy.ValidateRecoveryPolicy(p2)
	assert.ErrorContains(t, err, "claim_token_ttl_minutes must be between 5 and 60")

	// Rule 3: lockout_schedule (monotonically non-decreasing, >= 1h first step, 3-10 steps)
	p3a := valid
	p3a.LockoutSchedule = []string{"30m", "2h", "5h"} // first step < 1h
	err = policy.ValidateRecoveryPolicy(p3a)
	assert.ErrorContains(t, err, "lockout_schedule first step must be at least 1h")

	p3b := valid
	p3b.LockoutSchedule = []string{"2h", "1h", "5h"} // non-monotonic
	err = policy.ValidateRecoveryPolicy(p3b)
	assert.ErrorContains(t, err, "monotonically non-decreasing")

	p3c := valid
	p3c.LockoutSchedule = []string{"2h", "5h"} // too few steps (< 3)
	err = policy.ValidateRecoveryPolicy(p3c)
	assert.ErrorContains(t, err, "lockout_schedule must contain between 3 and 10 steps")

	// Rule 4: lockout_reset_days (7 - 90)
	p4 := valid
	p4.LockoutResetDays = 2
	err = policy.ValidateRecoveryPolicy(p4)
	assert.ErrorContains(t, err, "lockout_reset_days must be between 7 and 90")

	// Rule 5: trusted_device_window_days (30 - 365)
	p5 := valid
	p5.TrustedDeviceWindowDays = 15
	err = policy.ValidateRecoveryPolicy(p5)
	assert.ErrorContains(t, err, "trusted_device_window_days must be between 30 and 365")

	// Rule 6: min_guardians & max_guardians
	p6a := valid
	p6a.MinGuardians = 4
	p6a.MaxGuardians = 2 // min > max
	err = policy.ValidateRecoveryPolicy(p6a)
	assert.ErrorContains(t, err, "min_guardians (4) cannot exceed max_guardians (2)")

	p6b := valid
	p6b.MaxGuardians = 6 // > 5
	err = policy.ValidateRecoveryPolicy(p6b)
	assert.ErrorContains(t, err, "max_guardians must be <= 5")

	// Rule 7: At least ONE method toggle enabled
	p7 := valid
	p7.GuardiansEnabled = false
	p7.PhoneOTPEnabled = false
	p7.EmailOTPEnabled = false
	p7.OldPasswordEnabled = false
	p7.SecurityQuestionsEnabled = false
	err = policy.ValidateRecoveryPolicy(p7)
	assert.ErrorContains(t, err, "at least one recovery method toggle must remain enabled tenant-wide")

	// Rule 8: Subnet bit boundaries (IPv4: 16-30, IPv6: 32-64)
	p8 := valid
	p8.IPv4SubnetBits = 8
	err = policy.ValidateRecoveryPolicy(p8)
	assert.ErrorContains(t, err, "ipv4_subnet_bits must be between 16 and 30")

	// Rule 9: max_proof_attempts_per_window (1 - 10)
	p9 := valid
	p9.MaxProofAttemptsPerWindow = 15
	err = policy.ValidateRecoveryPolicy(p9)
	assert.ErrorContains(t, err, "max_proof_attempts_per_window must be between 1 and 10")
}

func TestGetAndUpdateRecoveryPolicy_Repository(t *testing.T) {
	dbName := fmt.Sprintf("file:ent_policy_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := policy.NewRepository(factory)
	// The privacy interceptors require a scope, and a policy write does not
	// create a missing tenant, so the fixture provisions one up front.
	ctx := privacy.NewBypassContext(context.Background())

	tenantID := "tnt_policy_test"

	_, err = factory.GetClient(ctx, tenantID, "test").Tenant.Create().
		SetID(tenantID).
		SetName("Policy Test Workspace").
		SetSlug(tenantID).
		Save(ctx)
	require.NoError(t, err)

	// 1. Default Fallback
	pDef, err := repo.GetRecoveryPolicy(ctx, tenantID)
	require.NoError(t, err)
	assert.True(t, pDef.GuardiansEnabled)
	assert.Equal(t, 48, pDef.FreezeWindowHours)

	// 2. Update Valid Custom Policy
	custom := policy.DefaultRecoveryPolicy()
	custom.GuardiansEnabled = false
	custom.FreezeWindowHours = 72

	updated, err := repo.UpdateRecoveryPolicy(ctx, tenantID, custom)
	require.NoError(t, err)
	assert.False(t, updated.GuardiansEnabled)
	assert.Equal(t, 72, updated.FreezeWindowHours)

	// 3. Read back persisted policy
	readBack, err := repo.GetRecoveryPolicy(ctx, tenantID)
	require.NoError(t, err)
	assert.False(t, readBack.GuardiansEnabled)
	assert.Equal(t, 72, readBack.FreezeWindowHours)
}
