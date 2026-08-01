/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/services/auth_service_test.go
 * Tier: Domain Logic Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package services_test

import (
	"context"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/repository"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthService_Argon2idHashing(t *testing.T) {
	cfg := &config.EnvConfig{
		AuthnAPIKeyPepper: "test_pepper_key_32_bytes_long_12345",
	}
	factory, err := repository.NewClientFactory("sqlite3", "file:ent_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := repository.NewAuthRepository(factory)
	svc := services.NewAuthService(repo, cfg)

	password := "SecurePassword123!"
	hash, err := svc.HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$argon2id$v=19$m=65536,t=3,p=4$")
}

func TestAuthService_ValidateApiKey_InvalidKey(t *testing.T) {
	cfg := &config.EnvConfig{
		AuthnAPIKeyPepper: "test_pepper_key_32_bytes_long_12345",
	}
	factory, err := repository.NewClientFactory("sqlite3", "file:ent_test2?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := repository.NewAuthRepository(factory)
	svc := services.NewAuthService(repo, cfg)

	ctx := context.Background()
	_, err = svc.ValidateApiKey(ctx, "invalid_key_prefix_999")
	assert.ErrorIs(t, err, services.ErrInvalidApiKey)
}
