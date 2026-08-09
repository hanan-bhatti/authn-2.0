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
	seedTenantID = "tnt_default"
	seedAppID    = "app_test123"
	seedOrgID    = "org_acme"
	seedOrgName  = "Acme Corp"
	seedOrgSlug  = "acme-corp"
)
