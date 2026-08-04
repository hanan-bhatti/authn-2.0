/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/service_test.go
 * Tier: Internal Feature Package / Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth_test

import (
	"context"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrypto_Argon2idPasswordHashing(t *testing.T) {
	password := "SecurePassword123!"
	hash, err := crypto.HashPasswordArgon2id(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	match := crypto.VerifyPasswordArgon2id(password, hash)
	assert.True(t, match)

	wrongMatch := crypto.VerifyPasswordArgon2id("WrongPassword", hash)
	assert.False(t, wrongMatch)
}

func TestAuthService_ValidateApiKey_Invalid(t *testing.T) {
	cfg := &config.EnvConfig{
		AuthnAPIKeyPepper: "test_pepper_key_32_bytes_long_12345",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_auth_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	svc := auth.NewService(repo, cfg, nil)

	ctx := context.Background()
	_, err = svc.ValidateApiKey(ctx, "invalid_key_prefix_999")
	assert.ErrorIs(t, err, auth.ErrInvalidApiKey)
}

func TestAuthService_SignUpAndLogin(t *testing.T) {
	cfg := &config.EnvConfig{
		AuthnAPIKeyPepper:  "test_pepper_key_32_bytes_long_12345",
		AuthnEncryptionKey: "test_encryption_key_32_bytes_12345",
	}
	factory, err := clientfactory.NewClientFactory("sqlite3", "file:ent_signup_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := auth.NewRepository(factory)
	svc := auth.NewService(repo, cfg, nil)

	ctx := privacy.NewContext(context.Background(), "tnt_test", "", "test")

	// 1. Test Signup
	u, accessTok, refreshTok, err := svc.SignUpWithPassword(ctx, "tnt_test", "test", "testuser@example.com", "MyPassword123!", "Test User", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)
	assert.NotEmpty(t, u.ID)
	assert.Equal(t, "testuser@example.com", u.Email)
	assert.NotEmpty(t, accessTok)
	assert.NotEmpty(t, refreshTok)

	// 2. Test Duplicate Signup
	_, _, _, err = svc.SignUpWithPassword(ctx, "tnt_test", "test", "testuser@example.com", "MyPassword123!", "Test User", "Mozilla/5.0", "127.0.0.1")
	assert.ErrorIs(t, err, auth.ErrUserAlreadyExists)

	// 3. Test Valid Login
	uLogin, accessTok2, refreshTok2, err := svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "testuser@example.com", "MyPassword123!", "Mozilla/5.0", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, u.ID, uLogin.ID)
	assert.NotEmpty(t, accessTok2)
	assert.NotEmpty(t, refreshTok2)

	// 4. Test Invalid Password Login
	_, _, _, err = svc.ValidatePasswordCredentials(ctx, "tnt_test", "test", "testuser@example.com", "WrongPassword!", "Mozilla/5.0", "127.0.0.1")
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}
