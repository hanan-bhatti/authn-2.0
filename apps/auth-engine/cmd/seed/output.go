/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/output.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: Development seed summary printer logic for stdout.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"fmt"
)

// printSummary writes the seeded credentials to stdout.
//
// It goes to stdout rather than the log because it is the operator-facing
// result of the command — the thing a developer copies a password out of —
// while the log carries progress and diagnostics.
func printSummary(specs []userSpec) {
	fmt.Println()
	fmt.Println("Development seed data installed. These credentials are public; do not reuse them.")
	fmt.Println()
	fmt.Printf("  publishable key : %s\n", demoPublishableKey)
	fmt.Printf("  secret key      : %s\n", demoSecretKey)
	fmt.Printf("  organization    : %s (id %s, slug %s)\n", seedOrgName, seedOrgID, seedOrgSlug)
	fmt.Println()
	fmt.Println("  accounts:")
	for _, spec := range specs {
		fmt.Printf("    %-30s %-14s %s\n", spec.Email, spec.Password, spec.State)
	}
	fmt.Println()
}
