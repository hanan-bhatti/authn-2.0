/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/bootstrap/output.go
 * Tier: Provisioning CLI / Operator Output
 *
 * Description: Formats the provisioning result for the operator running the
 *              command. The secret key is displayed here and nowhere else,
 *              ever again, so the output has to make that unmistakable.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"fmt"
	"os"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/provisioning"
)

// reportProvisioned prints the credentials for a newly created tenant.
//
// Only the hash of each key is stored, so this is the single moment the raw
// values exist anywhere. An operator who closes the terminal without copying
// the secret key cannot recover it and must mint a replacement, which is why
// the warning is adjacent to the value rather than in a footnote.
func reportProvisioned(res *provisioning.Result) {
	out := os.Stdout

	fmt.Fprintf(out, "\nTenant provisioned.\n\n")
	fmt.Fprintf(out, "  Tenant       %s  (%s)\n", res.TenantID, res.TenantSlug)
	fmt.Fprintf(out, "  Application  %s\n", res.ApplicationID)
	fmt.Fprintf(out, "  Environment  %s\n", res.Environment)
	fmt.Fprintf(out, "  Roles        %d installed\n", res.RolesInstalled)

	fmt.Fprintf(out, "\n  Publishable key — safe to ship in browser and mobile bundles:\n")
	fmt.Fprintf(out, "    %s\n", res.PublishableKey)

	if res.SecretKey != "" {
		fmt.Fprintf(out, "\n  Secret key — server-side only. Shown once and never recoverable:\n")
		fmt.Fprintf(out, "    %s\n", res.SecretKey)
	}

	fmt.Fprintf(out, "\nNext: configure your SDK with the publishable key, then sign up.\n")
	fmt.Fprintf(out, "The first account created becomes this tenant's administrator.\n\n")
}

// reportExisting prints the identifiers of a tenant that was already present.
//
// No credentials appear: Provision does not mint keys for an existing tenant,
// because a container entrypoint re-running this command on every restart would
// otherwise accumulate live secret keys nobody has seen. Recovering from a lost
// key is a deliberate act through the key-management API, not a side effect of
// a restart.
func reportExisting(res *provisioning.Result) {
	out := os.Stdout

	fmt.Fprintf(out, "\nTenant %q already exists — nothing to do.\n\n", res.TenantSlug)
	fmt.Fprintf(out, "  Tenant       %s\n", res.TenantID)
	fmt.Fprintf(out, "  Environment  %s\n", res.Environment)
	fmt.Fprintf(out, "\nNo new keys were minted. To issue a replacement key, use the\n")
	fmt.Fprintf(out, "key-management API with an existing secret key or admin session.\n\n")
}
