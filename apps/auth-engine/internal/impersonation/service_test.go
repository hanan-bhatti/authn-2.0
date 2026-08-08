/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/impersonation/service_test.go
 * Tier: Internal Feature Package / Impersonation Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package impersonation_test

import (
	"context"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/impersonation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImpersonationService(t *testing.T) {
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:impersonation_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tnt, err := client.Tenant.Create().SetID("tnt_imp").SetName("Impersonation Tenant").SetSlug("tnt-imp").Save(sysCtx)
	require.NoError(t, err)

	cfg := &config.Config{
		EncryptionKey: "test_encryption_key_32_bytes_12345",
	}
	svc := impersonation.NewService(factory, cfg)

	// Create Admin User & Target User & Other Admin User
	adminUser, err := client.User.Create().SetID("usr_admin1").SetTenantID(tnt.ID).SetEmail("admin@example.com").SetName("Admin User").SetStatus("active").Save(sysCtx)
	require.NoError(t, err)

	targetUser, err := client.User.Create().SetID("usr_target1").SetTenantID(tnt.ID).SetEmail("target@example.com").SetName("Target User").SetStatus("active").Save(sysCtx)
	require.NoError(t, err)

	otherAdmin, err := client.User.Create().SetID("usr_admin2").SetTenantID(tnt.ID).SetEmail("admin2@example.com").SetName("Other Admin").SetStatus("active").Save(sysCtx)
	require.NoError(t, err)

	// Assign admin role to otherAdmin
	roleAdmin, err := client.Role.Create().SetID("rol_admin").SetTenantID(tnt.ID).SetName("Tenant Admin").SetSlug("tenant_admin").Save(sysCtx)
	require.NoError(t, err)
	_, err = client.UserRole.Create().SetID("ur_admin2").SetUserID(otherAdmin.ID).SetRoleID(roleAdmin.ID).Save(sysCtx)
	require.NoError(t, err)

	defaultPol := policy.DefaultImpersonationPolicy() // max_duration = 15

	// 1. Valid Impersonation
	req1 := policy.ImpersonateRequest{
		Reason:          "Investigating user billing bug #1024",
		DurationMinutes: 10,
	}
	res1, err := svc.ExecuteImpersonation(sysCtx, tnt.ID, "test", adminUser.ID, targetUser.ID, req1, defaultPol)
	require.NoError(t, err)
	assert.NotEmpty(t, res1.AccessToken)
	assert.Equal(t, targetUser.ID, res1.ImpersonatedUser.ID)
	assert.Equal(t, adminUser.ID, res1.ImpersonatorID)
	assert.Equal(t, 600, res1.ExpiresIn) // 10 minutes

	// Verify claims on issued JWT
	claims, err := jwtpkg.VerifyAccessToken(res1.AccessToken, cfg.EncryptionKey)
	require.NoError(t, err)
	assert.Equal(t, targetUser.ID, claims.Sub)
	assert.Equal(t, adminUser.ID, claims.ImpersonatorID)
	assert.True(t, claims.IsImpersonated)

	// 2. Self-Impersonation Attempt -> Error
	_, err = svc.ExecuteImpersonation(sysCtx, tnt.ID, "test", adminUser.ID, adminUser.ID, req1, defaultPol)
	assert.ErrorIs(t, err, impersonation.ErrCannotImpersonateSelf)

	// 3. Impersonate Non-Existent User -> Error
	_, err = svc.ExecuteImpersonation(sysCtx, tnt.ID, "test", adminUser.ID, "usr_nonexistent", req1, defaultPol)
	assert.ErrorIs(t, err, impersonation.ErrUserNotFound)

	// 4. Impersonate another Admin User -> Error (ErrCannotImpersonateAdmin)
	_, err = svc.ExecuteImpersonation(sysCtx, tnt.ID, "test", adminUser.ID, otherAdmin.ID, req1, defaultPol)
	assert.ErrorIs(t, err, impersonation.ErrCannotImpersonateAdmin)

	// 5. Short Reason (< 10 chars) -> Error
	shortReq := policy.ImpersonateRequest{Reason: "test"}
	_, err = svc.ExecuteImpersonation(sysCtx, tnt.ID, "test", adminUser.ID, targetUser.ID, shortReq, defaultPol)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 10 characters")

	// 6. User Opt-In Required Policy Test
	optInPol := defaultPol
	optInPol.RequireUserOptIn = true

	// targetUser has no opt-in metadata -> Error
	_, err = svc.ExecuteImpersonation(sysCtx, tnt.ID, "test", adminUser.ID, targetUser.ID, req1, optInPol)
	assert.ErrorIs(t, err, impersonation.ErrUserOptInRequired)

	// Grant opt-in metadata to targetUser
	_, err = client.User.UpdateOneID(targetUser.ID).SetMetadata(map[string]interface{}{"support_access_enabled": true}).Save(sysCtx)
	require.NoError(t, err)

	// Now opt-in impersonation succeeds
	resOptIn, err := svc.ExecuteImpersonation(sysCtx, tnt.ID, "test", adminUser.ID, targetUser.ID, req1, optInPol)
	require.NoError(t, err)
	assert.Equal(t, targetUser.ID, resOptIn.ImpersonatedUser.ID)
}
