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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/provisioning"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// seedTenantAndApplication creates the demo tenant and its application.
//
// It goes through the ordinary provisioning path rather than writing the rows
// itself, so the seeded tenant is shaped exactly like one a real customer gets
// — same system roles, same application defaults. The identifiers are pinned
// because the demo credentials and the documentation reference them by name,
// and key generation is suppressed because the seeder installs its own fixed
// demo keys immediately afterwards.
//
// The reserved-slug guard is waived: "default" is on the reserved list, and
// this is the one caller entitled to claim it.
//
// Returns an error if either row is missing afterwards; everything else seeded
// below belongs to them, so there is no useful partial result.
func seedTenantAndApplication(ctx context.Context, svc *provisioning.Service) error {
	_, err := svc.Provision(ctx, provisioning.Request{
		Name:            "Default Workspace",
		Slug:            seedTenantSlug,
		Environment:     "test",
		ApplicationName: "Default Client App",
		RedirectURIs:    []string{"http://localhost:3000/callback"},
		AllowedCorsOrigins: []string{
			"http://localhost:3000",
			"http://localhost:5173",
		},
	}, provisioning.Options{
		TenantID:          seedTenantID,
		ApplicationID:     seedAppID,
		AllowReservedSlug: true,
		SkipKeys:          true,
	})
	if err != nil {
		return fmt.Errorf("seeding tenant %s: %w", seedTenantID, err)
	}
	return nil
}

// seedAPIKeys installs the demo publishable and secret keys against the seeded
// application, hashed with the configured pepper.
//
// These are fixed, published values rather than generated ones, which is why
// the seeder suppresses the pair Provision would have minted: the documentation
// and local SDK samples reference them literally.
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
