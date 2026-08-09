/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/guard.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: Production environment guard preventing demo seed execution against production database.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

// refuseProduction reports an error when the loaded configuration names the
// production tier.
//
// APP_ENV is consulted through the parsed configuration, and the raw
// environment is checked as well: an operator who exports ENV=production but
// not APP_ENV has stated their intent clearly enough, and the cost of honouring
// that is one refused development run.
func refuseProduction(cfg *config.Config) error {
	if cfg.IsProduction() {
		return fmt.Errorf("refusing to seed a production environment (APP_ENV=%s): "+
			"this command installs demo credentials that are published in source control", cfg.Env)
	}

	if raw := strings.ToLower(strings.TrimSpace(os.Getenv("ENV"))); raw == config.EnvProduction {
		return fmt.Errorf("refusing to seed: ENV=production is set in the environment")
	}
	return nil
}
