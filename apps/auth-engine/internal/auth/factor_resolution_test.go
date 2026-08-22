/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/factor_resolution_test.go
 * Tier: Internal Feature Package / Auth Service Tests
 *
 * Description: Covers how the second-factor set is resolved at sign-in: that an unreadable set
 *              refuses the sign-in rather than admitting a password on its own, that the offered
 *              methods are ordered by last use, and that a factor outside the challenge's set is
 *              refused before any code is tested.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

const factorTestEncryptionKey = "test_encryption_key_32_bytes_12345"

// newFactorTestService builds a service over its own in-memory database. The DSN is
// returned so a test can reach the same database outside ent, which is how the
// unreadable-factor case below is staged.
func newFactorTestService(t *testing.T, dsn string) (*auth.Service, *auth.Repository, string) {
	t.Helper()

	cfg := &config.Config{
		APIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		EncryptionKey: factorTestEncryptionKey,
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = factory.Close() })

	repo := auth.NewRepository(factory)
	require.NoError(t, repo.EnsureTenantExists(testCtx(), "tnt_test"))

	return auth.NewService(repo, cfg, nil), repo, dsn
}

// enableTOTP enrolls a TOTP factor and promotes it to active, returning its method ID.
func enableTOTP(t *testing.T, repo *auth.Repository, userID string) string {
	t.Helper()

	tfm, err := repo.CreateOrUpdatePendingTOTPSecret(testCtx(), "tfm_totp_"+userID, userID, "encrypted-totp-secret")
	require.NoError(t, err)
	require.NoError(t, repo.EnableTwoFactorMethod(testCtx(), tfm.ID))

	return tfm.ID
}

// TestLogin_RefusesWhenFactorSetUnreadable is the fail-closed property: a correct
// password must not open a session while the account's second factors cannot be read.
//
// The factor table is dropped rather than the whole database closed, because closing
// it would fail the password lookup too and the sign-in would be refused for the
// wrong reason — proving nothing about the gate.
func TestLogin_RefusesWhenFactorSetUnreadable(t *testing.T) {
	dsn := "file:ent_factor_unreadable?mode=memory&cache=shared&_fk=1"
	svc, repo, _ := newFactorTestService(t, dsn)
	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "failclosed@example.com", "MyPassword123!", "Fail Closed", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)
	enableTOTP(t, repo, u.ID)

	// The account is genuinely gated before anything is broken, so the assertion
	// below is about the read failing and not about the enrollment.
	_, _, _, err = svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "failclosed@example.com", "MyPassword123!", "Mozilla/5.0", "127.0.0.1")
	require.ErrorIs(t, err, auth.Err2FARequired)

	raw, err := sql.Open("sqlite3", dsn)
	require.NoError(t, err)
	defer raw.Close()
	_, err = raw.Exec("DROP TABLE two_factor_methods")
	require.NoError(t, err)

	user, accessToken, refreshToken, err := svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "failclosed@example.com", "MyPassword123!", "Mozilla/5.0", "127.0.0.1")

	require.ErrorIs(t, err, auth.ErrFactorsUnavailable,
		"an unreadable factor set must refuse the sign-in, not resolve to no second factor")
	assert.Nil(t, user)
	assert.Empty(t, accessToken, "no access token may be issued when the factor set is unknown")
	assert.Empty(t, refreshToken, "no session may be opened when the factor set is unknown")

	// The distinction that matters to a client: this is not a credential failure, so
	// it must not route to the same answer a wrong password gets.
	assert.NotErrorIs(t, err, auth.ErrInvalidCredentials)
}

// TestLogin_OffersFactorsMostRecentlyUsedFirst pins the order of the challenge's
// method list, which is what a login screen shows first and hides behind "try
// another way".
func TestLogin_OffersFactorsMostRecentlyUsedFirst(t *testing.T) {
	svc, repo, _ := newFactorTestService(t, "file:ent_factor_order?mode=memory&cache=shared&_fk=1")
	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "ordering@example.com", "MyPassword123!", "Ordering", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)

	totpID := enableTOTP(t, repo, u.ID)
	passkey, err := repo.CreateWebAuthnPasskey(testCtx(), u.ID, "Laptop", "credential-id-1", []byte("public-key"), 0, nil)
	require.NoError(t, err)

	offered := func() []string {
		_, mfaToken, _, err := svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "ordering@example.com", "MyPassword123!", "Mozilla/5.0", "127.0.0.1")
		require.ErrorIs(t, err, auth.Err2FARequired)
		claims, vErr := jwtpkg.VerifyMFAChallengeToken(mfaToken, factorTestEncryptionKey)
		require.NoError(t, vErr)
		return claims.Methods
	}

	// Never used: the fixed collection order stands, so a first challenge looks the
	// same for every account holding these two factors.
	assert.Equal(t, []string{"totp", "passkey"}, offered())

	require.NoError(t, repo.UpdateTwoFactorMethodLastUsed(testCtx(), passkey.ID))
	assert.Equal(t, []string{"passkey", "totp"}, offered(),
		"the factor used last must be offered first")

	// Stamps are compared, not merely present, so the older factor moving back to the
	// front has to overtake a real timestamp rather than a zero one.
	time.Sleep(5 * time.Millisecond)
	require.NoError(t, repo.UpdateTwoFactorMethodLastUsed(testCtx(), totpID))
	assert.Equal(t, []string{"totp", "passkey"}, offered())
}

// TestLogin_RecoveryCodesStayLast keeps backup codes at the end of the list however
// recently one was redeemed: they are a way past a factor rather than a factor, and a
// challenge that opened on them would spend a finite code by default.
func TestLogin_RecoveryCodesStayLast(t *testing.T) {
	svc, repo, _ := newFactorTestService(t, "file:ent_factor_backup_last?mode=memory&cache=shared&_fk=1")
	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "backuplast@example.com", "MyPassword123!", "Backup Last", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)

	enableTOTP(t, repo, u.ID)
	_, err = svc.GenerateRecoveryCodes(testCtx(), u.ID)
	require.NoError(t, err)

	_, mfaToken, _, err := svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "backuplast@example.com", "MyPassword123!", "Mozilla/5.0", "127.0.0.1")
	require.ErrorIs(t, err, auth.Err2FARequired)
	claims, err := jwtpkg.VerifyMFAChallengeToken(mfaToken, factorTestEncryptionKey)
	require.NoError(t, err)

	require.Equal(t, []string{"totp", "backup_code"}, claims.Methods)
}

// TestVerify2FA_RefusesFactorOutsideChallengeSet covers the set fixed at password
// time. Each verifier also rejects an unenrolled factor on its own, so this asserts
// the contract rather than the coincidence: the refusal must come before any code is
// tested, whatever the individual verifiers happen to do.
func TestVerify2FA_RefusesFactorOutsideChallengeSet(t *testing.T) {
	svc, repo, _ := newFactorTestService(t, "file:ent_factor_outside_set?mode=memory&cache=shared&_fk=1")
	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "outsideset@example.com", "MyPassword123!", "Outside Set", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)
	enableTOTP(t, repo, u.ID)

	_, mfaToken, _, err := svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "outsideset@example.com", "MyPassword123!", "Mozilla/5.0", "127.0.0.1")
	require.ErrorIs(t, err, auth.Err2FARequired)

	// The account holds TOTP alone, so naming backup codes reaches for a factor the
	// challenge never offered.
	_, _, _, err = svc.VerifyTOTPChallenge(ctx, mfaToken, "12345678", "backup_code", "Mozilla/5.0", "127.0.0.1")
	require.ErrorIs(t, err, auth.ErrFactorUnavailable)
}

// TestVerify2FA_PasskeyNamesItsOwnRoute keeps a client that walks the offered methods
// from concluding passkeys are unsupported. They are verified by signing an assertion,
// so the answer names where that happens rather than reporting an unknown method.
func TestVerify2FA_PasskeyNamesItsOwnRoute(t *testing.T) {
	svc, repo, _ := newFactorTestService(t, "file:ent_factor_passkey_route?mode=memory&cache=shared&_fk=1")
	ctx := privacy.NewContext(testCtx(), "tnt_test", "", "test")

	u, _, _, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "passkeyroute@example.com", "MyPassword123!", "Passkey Route", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)
	_, err = repo.CreateWebAuthnPasskey(testCtx(), u.ID, "Laptop", "credential-id-2", []byte("public-key"), 0, nil)
	require.NoError(t, err)

	_, mfaToken, _, err := svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "passkeyroute@example.com", "MyPassword123!", "Mozilla/5.0", "127.0.0.1")
	require.ErrorIs(t, err, auth.Err2FARequired)

	_, _, _, err = svc.VerifyTOTPChallenge(ctx, mfaToken, "123456", "passkey", "Mozilla/5.0", "127.0.0.1")
	require.ErrorIs(t, err, auth.ErrPasskeyVerificationRoute)
}
