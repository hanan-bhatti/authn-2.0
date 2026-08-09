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
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/database"
)

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

// seedTenantAndApplication creates the default tenant and the application that
// owns the demo API keys.
//
// Returns an error if either is missing afterwards; everything else seeded
// below belongs to them, so there is no useful partial result.
func seedTenantAndApplication(ctx context.Context, factory *clientfactory.ClientFactory) error {
	authRepo := auth.NewRepository(factory)

	if err := authRepo.EnsureTenantExists(ctx, seedTenantID); err != nil {
		return fmt.Errorf("seeding tenant %s: %w", seedTenantID, err)
	}
	if err := authRepo.EnsureDefaultApplicationExists(ctx, seedAppID, seedTenantID,
		[]string{"http://localhost:3000/callback"}); err != nil {
		return fmt.Errorf("seeding application %s: %w", seedAppID, err)
	}
	return nil
}

// seedAPIKeys installs the demo publishable and secret keys against the seeded
// application, hashed with the configured pepper.
//
// Returns an error when either key cannot be stored, since an SDK configured
// from the printed summary would then fail to authenticate.
func seedAPIKeys(ctx context.Context, factory *clientfactory.ClientFactory, pepper string) error {
	apiKeyRepo := apikey.NewRepository(factory)

	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_pk_demo123", seedAppID, demoPublishableKey, pepper); err != nil {
		return fmt.Errorf("seeding publishable key: %w", err)
	}
	if err := apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_sk_demo123", seedAppID, demoSecretKey, pepper); err != nil {
		return fmt.Errorf("seeding secret key: %w", err)
	}
	return nil
}

// seedRoles creates the system roles and returns them keyed by slug.
//
// Returns an error when a role cannot be created, because the user and
// organization steps assign these roles by the IDs recorded here.
func seedRoles(ctx context.Context, client *ent.Client) (map[string]*ent.Role, error) {
	definitions := []struct {
		ID   string
		Name string
		Slug string
	}{
		{"role_tenant_admin", "Tenant Administrator", "tenant_admin"},
		{"role_org_admin", "Organization Administrator", "org_admin"},
		{"role_editor", "Editor", "editor"},
		{"role_viewer", "Viewer", "viewer"},
	}

	roles := make(map[string]*ent.Role, len(definitions))
	for _, def := range definitions {
		existing, err := client.Role.Query().
			Where(role.TenantID(seedTenantID), role.Slug(def.Slug)).
			Only(ctx)
		if err == nil {
			roles[def.Slug] = existing
			continue
		}

		created, err := client.Role.Create().
			SetID(def.ID).
			SetTenantID(seedTenantID).
			SetName(def.Name).
			SetSlug(def.Slug).
			SetDescription("System role for " + def.Name).
			SetIsSystemRole(true).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("seeding role %s: %w", def.Slug, err)
		}
		roles[def.Slug] = created
	}
	return roles, nil
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

// seedOrganization creates the demo organization, adds the administrator and
// the member account to it, and attaches a SAML connection so the enterprise
// single sign-on path has a configured tenant to exercise.
//
// Returns an error when the organization or a membership cannot be written.
func seedOrganization(ctx context.Context, client *ent.Client, users map[string]*ent.User) error {
	org, err := client.Organization.Query().Where(organization.ID(seedOrgID)).Only(ctx)
	if err != nil {
		org, err = client.Organization.Create().
			SetID(seedOrgID).
			SetTenantID(seedTenantID).
			SetName(seedOrgName).
			SetSlug(seedOrgSlug).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("seeding organization %s: %w", seedOrgID, err)
		}
	}

	memberships := []struct {
		membershipID string
		email        string
		roleID       string
	}{
		{"mem_admin_acme", "admin@authn.local", "role_org_admin"},
		{"mem_user_acme", "user.orgmember@authn.local", "role_editor"},
	}

	for _, m := range memberships {
		u, ok := users[m.email]
		if !ok {
			return fmt.Errorf("organization member %s was not seeded", m.email)
		}

		exists, err := client.OrgMember.Query().
			Where(orgmember.OrganizationID(org.ID), orgmember.UserID(u.ID)).
			Exist(ctx)
		if err != nil {
			return fmt.Errorf("checking membership for %s: %w", m.email, err)
		}
		if exists {
			continue
		}

		if _, err := client.OrgMember.Create().
			SetID(m.membershipID).
			SetOrganizationID(org.ID).
			SetUserID(u.ID).
			SetRoleID(m.roleID).
			Save(ctx); err != nil {
			return fmt.Errorf("adding %s to organization: %w", m.email, err)
		}
	}

	return seedSAMLConnection(ctx, client, org.ID)
}

// seedSAMLConnection attaches a placeholder identity provider to the
// organization, unless one is already configured.
//
// The certificate and endpoints are not real. They exist so the SAML
// configuration screens and metadata endpoint have a record to render.
//
// Returns an error when the connection cannot be written.
func seedSAMLConnection(ctx context.Context, client *ent.Client, orgID string) error {
	configured, err := client.SAMLConnection.Query().
		Where(samlconnection.OrganizationID(orgID)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("checking existing SAML connection: %w", err)
	}
	if configured {
		return nil
	}

	if _, err := client.SAMLConnection.Create().
		SetID("saml_acme_corp").
		SetOrganizationID(orgID).
		SetIdpEntityID("https://idp.acme-corp.com/saml/metadata").
		SetIdpSSOURL("https://idp.acme-corp.com/saml/sso").
		SetIdpCertificate("-----BEGIN CERTIFICATE-----\nMIICXzCCAcegAwIBAgIU...\n-----END CERTIFICATE-----").
		SetAllowedDomains([]string{"acme-corp.com"}).
		SetEnforceSSO(true).
		Save(ctx); err != nil {
		return fmt.Errorf("seeding SAML connection: %w", err)
	}
	return nil
}

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
