/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/telemetry_test.go
 * Tier: Internal Feature Package / Telemetry & Trust Engine Tests
 *
 * Description: Automated test suite for IPv4/IPv6 subnet parsing, signed trusted device tokens,
 *              client fingerprinting, familiarity scoring, and 90-day telemetry auto-purge.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSubnet_IPv4AndIPv6(t *testing.T) {
	tests := []struct {
		ip              string
		expectedSubnet  string
		expectedVersion int
		wantErr         bool
	}{
		{ip: "198.51.100.45", expectedSubnet: "198.51.100.0/24", expectedVersion: 4, wantErr: false},
		{ip: "10.0.0.1", expectedSubnet: "10.0.0.0/24", expectedVersion: 4, wantErr: false},
		{ip: "2001:db8:abcd:0012::1", expectedSubnet: "2001:db8:abcd::/48", expectedVersion: 6, wantErr: false},
		{ip: "invalid-ip", expectedSubnet: "", expectedVersion: 0, wantErr: true},
	}

	for _, tt := range tests {
		subnet, ver, err := auth.ParseSubnet(tt.ip)
		if tt.wantErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedSubnet, subnet)
			assert.Equal(t, tt.expectedVersion, ver)
		}
	}
}

func TestGenerateAndVerifySignedDeviceToken(t *testing.T) {
	kmsKey := "super_secret_kms_key_32bytes_authn!"

	rawCookie, hash, err := auth.GenerateSignedDeviceToken(kmsKey)
	require.NoError(t, err)
	assert.NotEmpty(t, rawCookie)
	assert.Len(t, hash, 64)

	// Verify valid token
	hashVerified, valid := auth.VerifySignedDeviceToken(rawCookie, kmsKey)
	assert.True(t, valid)
	assert.Equal(t, hash, hashVerified)

	// Tampered signature MUST fail
	tamperedCookie := rawCookie[:len(rawCookie)-4] + "dead"
	_, valid = auth.VerifySignedDeviceToken(tamperedCookie, kmsKey)
	assert.False(t, valid)
}

func TestTelemetryService_TrustEvaluationAndRecord(t *testing.T) {
	kmsKey := "super_secret_kms_key_32bytes_authn!"
	dbName := fmt.Sprintf("file:ent_telemetry_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)
	policyRepo := policy.NewRepository(factory)
	svc := auth.NewTelemetryService(repo, kmsKey, policyRepo)
	ctx := testCtx()

	tenantID := "tnt_test_telemetry"
	err = repo.EnsureTenantExists(ctx, tenantID)
	require.NoError(t, err)

	client := factory.GetClient(ctx, tenantID, "test")

	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err = client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("telemetry@example.com").
		SetPasswordHash("hashed_password").
		Save(ctx)
	require.NoError(t, err)

	// 1. Initial login from 198.51.100.10
	ip1 := "198.51.100.10"
	ua1 := "Mozilla/5.0 (macOS; Chrome/128)"
	lang1 := "en-US,en"

	cookie1, err := svc.RecordSuccessfulLoginTelemetry(ctx, userID, "", ip1, ua1, lang1)
	require.NoError(t, err)
	assert.NotEmpty(t, cookie1)

	// 2. Evaluate trust from SAME device + subnet
	eval1, err := svc.EvaluateTrust(ctx, userID, cookie1, "198.51.100.88", ua1, lang1)
	require.NoError(t, err)
	assert.True(t, eval1.IsFamiliarSubnet, "Subnet 198.51.100.0/24 MUST be familiar")
	assert.True(t, eval1.IsRecognizedDevice, "Signed device cookie MUST be recognized")

	// 3. Evaluate trust from UNFAMILIAR subnet (203.0.113.50)
	eval2, err := svc.EvaluateTrust(ctx, userID, cookie1, "203.0.113.50", ua1, lang1)
	require.NoError(t, err)
	assert.False(t, eval2.IsFamiliarSubnet, "Subnet 203.0.113.0/24 MUST be unfamiliar")
	assert.True(t, eval2.IsRecognizedDevice, "Device cookie remains recognized")
}

func TestTelemetryService_PurgeExpiredTelemetry(t *testing.T) {
	kmsKey := "super_secret_kms_key_32bytes_authn!"
	dbName := fmt.Sprintf("file:ent_purge_%s?mode=memory&cache=shared&_fk=1", uuid.New().String()[:8])
	factory, err := clientfactory.NewClientFactory("sqlite3", dbName)
	require.NoError(t, err)
	t.Cleanup(func() { factory.Close() })

	repo := auth.NewRepository(factory)
	policyRepo := policy.NewRepository(factory)
	svc := auth.NewTelemetryService(repo, kmsKey, policyRepo)
	ctx := testCtx()

	tenantID := "tnt_test_purge"
	err = repo.EnsureTenantExists(ctx, tenantID)
	require.NoError(t, err)

	client := factory.GetClient(ctx, tenantID, "test")

	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	_, err = client.User.Create().
		SetID(userID).
		SetTenantID(tenantID).
		SetEmail("purge@example.com").
		SetPasswordHash("hashed_password").
		Save(ctx)
	require.NoError(t, err)

	// Create expired subnet entry (seen 95 days ago)
	oldTime := time.Now().Add(-95 * 24 * time.Hour)
	_, err = client.UserIpSubnetHistory.Create().
		SetID("sub_old_123").
		SetUserID(userID).
		SetSubnet("192.0.2.0/24").
		SetIPVersion(4).
		SetFirstSeenAt(oldTime).
		SetLastSeenAt(oldTime).
		Save(ctx)
	require.NoError(t, err)

	// Execute purge
	purgedSubnets, purgedDevices, err := svc.PurgeExpiredTelemetry(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, purgedSubnets, "Expired subnet >90 days old MUST be purged")
	assert.Equal(t, 0, purgedDevices)
}
