/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/seed_core.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: Core tenant, application, and API key seeder logic.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// seedTenantAndApplication creates the default tenant and the application that
// owns the demo API keys.
//
// Returns an error if either is missing afterwards; everything else seeded
// below belongs to them, so there is no useful partial result.
func seedTenantAndApplication(ctx context.Context, factory *clientfactory.ClientFactory) error {
	authRepo := auth.NewRepository(factory)

	if err := authRepo.EnsureTenantExists(ctx, seedTenantID); err != nil {
		return fmt.Errorf("seeding tenant %s: %w", seedTenantID, err)
	}
	if err := authRepo.EnsureDefaultApplicationExists(ctx, seedAppID, seedTenantID,
		[]string{"http://localhost:3000/callback"}); err != nil {
		return fmt.Errorf("seeding application %s: %w", seedAppID, err)
	}
	return nil
}

// seedAPIKeys installs the demo publishable and secret keys against the seeded
// application, hashed with the configured pepper.
//
// Returns an error when either key cannot be stored, since an SDK configured
// from the printed summary would then fail to authenticate.
func seedAPIKeys(ctx context.Context, factory *clientfactory.ClientFactory, pepper string) error {
	apiKeyRepo := apikey.NewRepository(factory)

	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_pk_demo123", seedAppID, demoPublishableKey, pepper); err != nil {
		return fmt.Errorf("seeding publishable key: %w", err)
	}
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_sk_demo123", seedAppID, demoSecretKey, pepper); err != nil {
		return fmt.Errorf("seeding secret key: %w", err)
	}
	return nil
}
