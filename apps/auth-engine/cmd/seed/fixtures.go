/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/fixtures.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: Demo user specifications and fixture dataset definitions.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
)

// userSpec describes one account to seed.
type userSpec struct {
	// ID is the fixed primary key, so repeated runs address the same row.
	ID string
	// Email is the sign-in address and the natural key used to detect an
	// account that a previous run already created.
	Email string
	// Password is the plaintext password, hashed with Argon2id on creation.
	Password string
	// EmailVerified sets the starting verification state, so both the verified
	// and unverified paths have an account to exercise.
	EmailVerified bool
	// State is a short human description shown in the summary.
	State string
	// setUp attaches records that depend on the created user, such as an
	// enrolled second factor. It is nil for accounts that need nothing extra.
	setUp func(ctx context.Context, client *ent.Client, roles map[string]*ent.Role, u *ent.User) error
}

// demoUsers returns the accounts to seed. Each covers a state worth having on
// hand during development: an administrator, an account with a second factor
// enrolled, an unverified account, an organization member, an account with
// recovery guardians, and one with no special state at all.
func demoUsers() []userSpec {
	return []userSpec{
		{
			ID:            "usr_admin_001",
			Email:         "admin@authn.local",
			Password:      demoAdminPassword,
			EmailVerified: true,
			State:         "tenant administrator",
			setUp:         assignTenantAdminRole,
		},
		{
			ID:            "usr_totp_002",
			Email:         "user.totp@authn.local",
			Password:      demoUserPassword,
			EmailVerified: true,
			State:         "TOTP enrolled (secret " + demoTOTPSecret + ")",
			setUp:         enrolTOTP,
		},
		{
			ID:            "usr_unverified_003",
			Email:         "user.unverified@authn.local",
			Password:      demoUserPassword,
			EmailVerified: false,
			State:         "email unverified",
		},
		{
			ID:            "usr_orgmember_004",
			Email:         "user.orgmember@authn.local",
			Password:      demoUserPassword,
			EmailVerified: true,
			State:         "organization member (Acme Corp, editor)",
		},
		{
			ID:            "usr_guardians_005",
			Email:         "user.guardians@authn.local",
			Password:      demoUserPassword,
			EmailVerified: true,
			State:         "account recovery guardian configured",
			setUp:         enrolRecoveryGuardian,
		},
		{
			ID:            "usr_vanilla_007",
			Email:         "user.vanilla@authn.local",
			Password:      demoUserPassword,
			EmailVerified: true,
			State:         "active, no special state",
		},
	}
}
