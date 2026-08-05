/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/mandatory_admin_2fa_test.go
 * Tier: Internal Feature Package / Security Unit Tests
 *
 * Description: Unit tests for Mandatory Admin 2FA enforcement.
 *              Verifies that administrative accounts cannot disable 2FA when it is
 *              their sole active primary 2FA method.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMandatoryAdmin2FA(t *testing.T) {
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:mandatory_admin_2fa_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, "", "")

	tnt, err := client.Tenant.Create().SetID("tnt_m2fa").SetName("Mandatory 2FA Tenant").SetSlug("tnt-m2fa").Save(sysCtx)
	require.NoError(t, err)

	cfg := &config.EnvConfig{
		AuthnEncryptionKey: "test_encryption_key_32_bytes_12345",
		AuthnAPIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
	}
	emailProv := email.NewNoopProvider()
	repo := auth.NewRepository(factory)
	svc := auth.NewService(repo, cfg, emailProv)

	// 1. Create Admin User via SignUpWithPassword
	adminUser, _, _, err := svc.SignUpWithPassword(sysCtx, tnt.ID, "test", "admin.mandatory2fa@example.com", "AdminPassword123!", "Admin User", "web", "127.0.0.1")
	require.NoError(t, err)

	// Assign tenant_admin role to user in DB
	roleAdmin, err := client.Role.Create().SetID("rol_tenant_admin").SetTenantID(tnt.ID).SetName("Tenant Admin").SetSlug("tenant_admin").Save(sysCtx)
	require.NoError(t, err)
	_, err = client.UserRole.Create().SetID("ur_admin1").SetUserID(adminUser.ID).SetRoleID(roleAdmin.ID).Save(sysCtx)
	require.NoError(t, err)

	// 2. Enroll & Confirm TOTP 2FA for Admin
	totpResult, err := svc.EnrollTOTP(sysCtx, adminUser.ID)
	require.NoError(t, err)

	code, err := totp.GenerateCode(totpResult.Secret, time.Now())
	require.NoError(t, err)

	_, err = svc.ConfirmTOTP(sysCtx, adminUser.ID, code)
	require.NoError(t, err)

	// 3. Attempt to Disable TOTP for Admin -> MUST fail with ErrAdmin2FAMandatory
	err = svc.DisableTOTP(sysCtx, adminUser.ID, "AdminPassword123!", "Mozilla/5.0", "127.0.0.1")
	assert.ErrorIs(t, err, auth.ErrAdmin2FAMandatory)

	// 4. Enroll a second primary 2FA method (Passkey) for Admin
	_, err = repo.CreateWebAuthnPasskey(sysCtx, adminUser.ID, "YubiKey", "cred_12345", []byte("pubkeybytes"), 0, map[string]interface{}{})
	require.NoError(t, err)

	// Now active count is 2 (TOTP + Passkey) -> Disable TOTP MUST succeed
	err = svc.DisableTOTP(sysCtx, adminUser.ID, "AdminPassword123!", "Mozilla/5.0", "127.0.0.1")
	assert.NoError(t, err)

	// 5. Regular User (non-admin) 2FA test
	regUser, _, _, err := svc.SignUpWithPassword(sysCtx, tnt.ID, "test", "regular.user@example.com", "RegularPassword123!", "Regular User", "web", "127.0.0.1")
	require.NoError(t, err)

	totpReg, err := svc.EnrollTOTP(sysCtx, regUser.ID)
	require.NoError(t, err)
	codeReg, err := totp.GenerateCode(totpReg.Secret, time.Now())
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(sysCtx, regUser.ID, codeReg)
	require.NoError(t, err)

	// Regular user disabling sole 2FA method -> Allowed (NoError)
	err = svc.DisableTOTP(sysCtx, regUser.ID, "RegularPassword123!", "Mozilla/5.0", "127.0.0.1")
	assert.NoError(t, err)
}
