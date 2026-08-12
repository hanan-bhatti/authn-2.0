/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/constants.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: Demo credential constants and seed entity identifiers.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

// Demo credentials installed by this seeder. They are published in source
// control and must never reach a real deployment.
const (
	demoPublishableKey = "pk_test_demo12345678901234567890123456789012"
	demoSecretKey      = "sk_test_demo12345678901234567890123456789012"
	demoAdminPassword  = "AdminPass123!"
	demoUserPassword   = "UserPass123!"
	// demoTOTPSecret is the RFC 6238 test vector, so an authenticator app
	// enrolled with it produces codes that any TOTP implementation agrees on.
	demoTOTPSecret = "JBSWY3DPEHPK3PXP"
)

// Identifiers for the seeded tenant, application and organization.
const (
	seedTenantID = "tnt_00000000000000000000000000000001"
	// seedTenantSlug is the demo tenant's slug. It is on the reserved list, so
	// only the seeder — which waives that guard — may claim it.
	seedTenantSlug = "default"
	seedAppID      = "app_00000000000000000000000000000001"
	seedOrgID      = "org_00000000000000000000000000000001"
	seedOrgName    = "Acme Corp"
	seedOrgSlug    = "acme-corp"
)
