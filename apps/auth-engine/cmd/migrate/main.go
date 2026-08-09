/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/migrate/main.go
 * Tier: Database Migration CLI
 *
 * Applies the ORM schema to the configured database and exits.
 *
 * The engine selection follows the same rule as the server: the scheme of
 * DATABASE_URL decides whether this is PostgreSQL, MySQL or SQLite. Nothing
 * here names a driver, so the migration cannot be applied to a different engine
 * than the one the server will open.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"log"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/database"
)

// main loads configuration, opens the configured database and creates or
// updates the schema.
//
// It exits non-zero on any failure: a configuration error, an unreachable
// database, or a migration the ORM could not apply. A partially migrated
// schema is reported rather than ignored, because the server that starts next
// would otherwise fail on a missing column at request time.
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error:\n%v", err)
	}

	log.Printf("migrate: starting database=%s", database.DescribeURL(cfg.DatabaseURL))

	// AutoMigrate is set explicitly rather than read from cfg.DatabaseAutoMigrate:
	// running the migration is this command's entire purpose, and honouring a
	// DATABASE_AUTO_MIGRATE=false setting here would make it silently do nothing.
	factory, err := clientfactory.NewFromURL(cfg.DatabaseURL, clientfactory.PoolOptions{
		MaxOpenConns:    cfg.DatabaseMaxOpenConns,
		MaxIdleConns:    cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime: cfg.DatabaseConnMaxLifetime,
		AutoMigrate:     true,
	})
	if err != nil {
		log.Fatalf("migrate: schema migration failed: %v", err)
	}
	defer factory.Close()

	log.Println("migrate: schema migration completed")
}
