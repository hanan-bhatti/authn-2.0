/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/main.go
 * Tier: Development Tool / Database Seeder
 *
 * DEVELOPMENT SEED DATA — NOT FOR PRODUCTION USE.
 *
 * Every credential in this file is a fixed, publicly known value committed to
 * source control: the demo publishable and secret API keys, the admin and user
 * passwords, and the TOTP seed on the pre-enrolled account. They are constants
 * on purpose, so a developer can clone the repository, seed, and sign in
 * without first inventing an account, and so tests and SDK examples can hard-
 * code a login that always works.
 *
 * That is exactly why this command refuses to run against a production
 * environment. Seeding a production database would install a tenant
 * administrator whose password is published in this repository.
 *
 * Seeding is idempotent: every record is created only when absent, so running
 * it repeatedly against a development database is safe.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"log"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/database"
)

// main seeds a development database and prints the credentials it installed.
//
// It exits non-zero when the environment is production, when configuration is
// invalid, when the database cannot be opened, or when a record that later
// steps depend on could not be created.
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error:\n%v", err)
	}

	// The guard sits before the database is opened so a misdirected run cannot
	// even establish a connection to a production instance.
	if err := refuseProduction(cfg); err != nil {
		log.Fatalf("seed: %v", err)
	}

	log.Printf("seed: starting env=%s database=%s",
		cfg.Env, database.DescribeURL(cfg.DatabaseURL))

	factory, err := clientfactory.NewFromURL(cfg.DatabaseURL, clientfactory.PoolOptions{
		MaxOpenConns:    cfg.DatabaseMaxOpenConns,
		MaxIdleConns:    cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime: cfg.DatabaseConnMaxLifetime,
		// The seeder creates the schema it is about to populate, so it works
		// against an empty database without a separate migrate run.
		AutoMigrate: true,
	})
	if err != nil {
		log.Fatalf("seed: database initialization failed: %v", err)
	}
	defer factory.Close()

	// Seeding writes across every tenant and environment, so it runs with the
	// privacy interceptor bypassed rather than scoped to one request's tenant.
	ctx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(ctx, seedTenantID, "")

	if err := seedTenantAndApplication(ctx, factory); err != nil {
		log.Fatalf("seed: %v", err)
	}
	if err := seedAPIKeys(ctx, factory, cfg.APIKeyPepper); err != nil {
		log.Fatalf("seed: %v", err)
	}

	roles, err := seedRoles(ctx, client)
	if err != nil {
		log.Fatalf("seed: %v", err)
	}

	specs := demoUsers()
	users, err := seedUsers(ctx, client, roles, specs)
	if err != nil {
		log.Fatalf("seed: %v", err)
	}

	if err := seedOrganization(ctx, client, users); err != nil {
		log.Fatalf("seed: %v", err)
	}

	log.Printf("seed: completed tenant=%s users=%d roles=%d", seedTenantID, len(users), len(roles))
	printSummary(specs)
}














