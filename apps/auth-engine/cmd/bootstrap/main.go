/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/bootstrap/main.go
 * Tier: Provisioning CLI
 *
 * Creates the first tenant on a fresh deployment and prints its credentials.
 *
 * Every route in the engine resolves its tenant from an API key, and API keys
 * belong to an application, which belongs to a tenant. On an empty database
 * there is no tenant, so there is no key, so there is no way in — and the
 * endpoint that mints keys is itself behind one. This command is the way out of
 * that circle.
 *
 * Unlike cmd/seed, this is production-safe. It installs no demo users, no
 * published passwords and no fixed key values; it creates one tenant with one
 * application and one freshly generated key pair. Running it against a live
 * database is the intended use, not an accident to be guarded against.
 *
 * It is idempotent by slug, so re-running it — which a container entrypoint may
 * do on every restart — reports the existing tenant rather than creating a
 * second one or failing.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/provisioning"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/database"
)

// main provisions a tenant from command-line flags and prints the result.
//
// It exits non-zero on a configuration error, an unreachable database, or
// invalid input. Diagnostics go to stderr through the logger; the credentials
// go to stdout, so a caller can capture them without also capturing log noise.
func main() {
	var (
		name        = flag.String("name", "", "organization name for the tenant (required)")
		slug        = flag.String("slug", "", "URL-friendly identifier (derived from -name when omitted)")
		environment = flag.String("env", "test", `environment for the first application and keys: "test" or "live"`)
		appName     = flag.String("app-name", "Default", "name for the tenant's first application")
		redirectURI = flag.String("redirect-uri", "", "initial OAuth redirect URI (repeatable via comma separation)")
		corsOrigin  = flag.String("cors-origin", "", "initial allowed browser origin (repeatable via comma separation)")
	)
	flag.Parse()

	if *name == "" {
		fmt.Fprintln(os.Stderr, "bootstrap: -name is required")
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error:\n%v", err)
	}

	log.Printf("bootstrap: starting env=%s database=%s",
		cfg.Env, database.DescribeURL(cfg.DatabaseURL))

	// The schema is created if absent, so this works against an empty database
	// without a separate migrate run — the common case on a first deployment.
	factory, err := clientfactory.NewFromURL(cfg.DatabaseURL, clientfactory.PoolOptions{
		MaxOpenConns:    cfg.DatabaseMaxOpenConns,
		MaxIdleConns:    cfg.DatabaseMaxIdleConns,
		ConnMaxLifetime: cfg.DatabaseConnMaxLifetime,
		AutoMigrate:     true,
	})
	if err != nil {
		log.Fatalf("bootstrap: database initialization failed: %v", err)
	}
	defer factory.Close()

	keys := apikey.NewService(apikey.NewRepository(factory), cfg.APIKeyPepper)
	svc := provisioning.NewService(factory, keys)

	res, err := svc.Provision(context.Background(), provisioning.Request{
		Name:               *name,
		Slug:               *slug,
		Environment:        *environment,
		ApplicationName:    *appName,
		RedirectURIs:       splitList(*redirectURI),
		AllowedCorsOrigins: splitList(*corsOrigin),
	}, provisioning.Options{
		ReservedSlugs: reservedSlugsFrom(cfg),
	})
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	if res.AlreadyExisted {
		reportExisting(res)
		return
	}
	reportProvisioned(res)
}

// reservedSlugsFrom returns the deployment's additional reserved slugs.
//
// The platform tenant's slug is reserved so that a self-hoster cannot
// accidentally provision over the control plane on a hosted deployment. On an
// installation with no platform tenant this is empty and only the built-in
// reservations apply.
func reservedSlugsFrom(cfg *config.Config) []string {
	if cfg.PlatformTenantSlug == "" {
		return nil
	}
	return []string{cfg.PlatformTenantSlug}
}

// splitList parses a comma-separated flag value into a trimmed, non-empty list.
func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
