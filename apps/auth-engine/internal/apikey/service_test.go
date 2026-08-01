/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/service_test.go
 * Tier: Internal Feature Package / Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package apikey_test

import (
	"context"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiKey_GeneratorAndRepository(t *testing.T) {
	pepper := "test_pepper_key_32_bytes_long_12345"
	gen, err := apikey.GenerateApiKey(apikey.TypeSecret, "test", pepper)
	require.NoError(t, err)
	assert.NotEmpty(t, gen.RawKey)
	assert.NotEmpty(t, gen.KeyHash)
	assert.Equal(t, "sk_test_", gen.Prefix)

	factory, err := clientfactory.NewClientFactory("sqlite3", "file:apikey_test?mode=memory&cache=shared&_fk=1")
	require.NoError(t, err)
	defer factory.Close()

	repo := apikey.NewRepository(factory)
	ctx := context.Background()

	// Seed tenant and application first
	client := factory.GetClient(ctx, "", "")
	tnt, err := client.Tenant.Create().
		SetID("tnt_test_123").
		SetName("Test Tenant").
		SetSlug("test-tenant").
		Save(ctx)
	require.NoError(t, err)

	app, err := client.Application.Create().
		SetID("app_test_123").
		SetTenantID(tnt.ID).
		SetName("Test Application").
		Save(ctx)
	require.NoError(t, err)

	k, err := repo.CreateApiKey(ctx, "key_123", app.ID, "Server Secret Key", gen.Type, gen.Prefix, gen.KeyHash, "test", nil)
	require.NoError(t, err)
	assert.Equal(t, "key_123", k.ID)

	found, err := repo.FindByHash(ctx, gen.KeyHash)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "key_123", found.ID)
}
