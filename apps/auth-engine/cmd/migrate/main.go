/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/migrate/main.go
 * Tier: Database Migration CLI
 *
 * Description: Command line utility to run Ent ORM automatic database schema
 *              migrations against the configured target database.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	log.Println("⚡ Authn Platform — Ent Schema Migration CLI")

	cfg, err := config.Load()
	driver := "postgres"
	dbURL := ""
	if err == nil && cfg != nil && cfg.DatabaseURL != "" {
		dbURL = cfg.DatabaseURL
	} else {
		dbURL = os.Getenv("DATABASE_URL")
	}

	if dbURL == "" {
		driver = "sqlite3"
		dbURL = "file:authn.db?cache=shared&_fk=1"
	}

	log.Printf("🔌 Connecting to %s database...", driver)
	client, err := ent.Open(driver, dbURL)
	if err != nil {
		log.Fatalf("❌ Failed connecting to database: %v", err)
	}
	defer client.Close()

	log.Println("🔄 Executing Ent ORM schema migration...")
	if err := client.Schema.Create(context.Background()); err != nil {
		log.Fatalf("❌ Migration failed: %v", err)
	}

	fmt.Println("✅ Ent ORM schema migration executed successfully!")
}
