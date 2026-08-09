/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/seed_users.go
 * Tier: Development Tool / Database Seeder
 *
 * Description: Demo user creation, role assignment, TOTP, and recovery guardian setup logic.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
)

// seedUsers creates each account that does not already exist and runs its
// setUp step. It returns the accounts keyed by email address.
//
// Returns an error when an account or its dependent records cannot be created.
// A half-seeded user is reported rather than skipped, because the organization
// step below looks these accounts up by address and would otherwise fail with a
// less obvious message.
func seedUsers(ctx context.Context, client *ent.Client, roles map[string]*ent.Role, specs []userSpec) (map[string]*ent.User, error) {
	users := make(map[string]*ent.User, len(specs))

	for _, spec := range specs {
		existing, err := client.User.Query().
			Where(user.TenantID(seedTenantID), user.Email(spec.Email)).
			Only(ctx)
		if err != nil {
			hash, hashErr := crypto.HashPasswordArgon2id(spec.Password)
			if hashErr != nil {
				return nil, fmt.Errorf("hashing password for %s: %w", spec.Email, hashErr)
			}

			existing, err = client.User.Create().
				SetID(spec.ID).
				SetTenantID(seedTenantID).
				SetEmail(spec.Email).
				SetPasswordHash(hash).
				SetEmailVerified(spec.EmailVerified).
				Save(ctx)
			if err != nil {
				return nil, fmt.Errorf("seeding user %s: %w", spec.Email, err)
			}
		}

		users[spec.Email] = existing

		if spec.setUp != nil {
			if err := spec.setUp(ctx, client, roles, existing); err != nil {
				return nil, fmt.Errorf("configuring user %s: %w", spec.Email, err)
			}
		}
	}
	return users, nil
}

// assignTenantAdminRole grants the tenant administrator role, unless the
// account already holds it. Returns an error when the grant cannot be written.
func assignTenantAdminRole(ctx context.Context, client *ent.Client, roles map[string]*ent.Role, u *ent.User) error {
	adminRole, ok := roles["tenant_admin"]
	if !ok {
		return fmt.Errorf("tenant_admin role was not seeded")
	}

	assigned, err := client.UserRole.Query().
		Where(userrole.UserID(u.ID), userrole.RoleID(adminRole.ID)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("checking existing role assignment: %w", err)
	}
	if assigned {
		return nil
	}

	if _, err := client.UserRole.Create().
		SetID("ur_admin_001").
		SetUserID(u.ID).
		SetRoleID(adminRole.ID).
		Save(ctx); err != nil {
		return fmt.Errorf("assigning tenant_admin: %w", err)
	}
	return nil
}

// enrolTOTP attaches a TOTP second factor carrying the published demo seed,
// unless one is already enrolled. Returns an error when it cannot be stored.
func enrolTOTP(ctx context.Context, client *ent.Client, _ map[string]*ent.Role, u *ent.User) error {
	enrolled, err := client.TwoFactorMethod.Query().
		Where(twofactormethod.UserID(u.ID), twofactormethod.TypeEQ(twofactormethod.TypeTotp)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("checking existing TOTP enrolment: %w", err)
	}
	if enrolled {
		return nil
	}

	if _, err := client.TwoFactorMethod.Create().
		SetID("tfm_totp_spec").
		SetUserID(u.ID).
		SetType(twofactormethod.TypeTotp).
		SetName("Authenticator App").
		SetSecretEncrypted(demoTOTPSecret).
		SetIsEnabled(true).
		Save(ctx); err != nil {
		return fmt.Errorf("enrolling TOTP: %w", err)
	}
	return nil
}

// enrolRecoveryGuardian creates a guardian account and links it as a recovery
// contact, so the guardian-based recovery flow has data to run against.
//
// Returns an error when the guardian account or the contact record cannot be
// created.
func enrolRecoveryGuardian(ctx context.Context, client *ent.Client, _ map[string]*ent.Role, u *ent.User) error {
	const guardianEmail = "guardian@authn.local"

	guardian, err := client.User.Query().Where(user.Email(guardianEmail)).Only(ctx)
	if err != nil {
		hash, hashErr := crypto.HashPasswordArgon2id(demoUserPassword)
		if hashErr != nil {
			return fmt.Errorf("hashing guardian password: %w", hashErr)
		}
		guardian, err = client.User.Create().
			SetID("usr_guardian_006").
			SetTenantID(seedTenantID).
			SetEmail(guardianEmail).
			SetPasswordHash(hash).
			SetEmailVerified(true).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("creating guardian account: %w", err)
		}
	}

	linked, err := client.RecoveryContact.Query().
		Where(recoverycontact.UserID(u.ID), recoverycontact.GuardianEmail(guardianEmail)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("checking existing recovery contact: %w", err)
	}
	if linked {
		return nil
	}

	if _, err := client.RecoveryContact.Create().
		SetID("rec_c_" + uuid.New().String()[:8]).
		SetUserID(u.ID).
		SetGuardianEmail(guardian.Email).
		SetGuardianName("Trusted Guardian").
		SetShareIndex(1).
		SetShareHash("mock_share_hash_12345678901234567890123456789012").
		SetStatus("active").
		Save(ctx); err != nil {
		return fmt.Errorf("linking recovery contact: %w", err)
	}
	return nil
}
