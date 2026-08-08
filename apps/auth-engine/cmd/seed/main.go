/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/seed/main.go
 * Tier: Development & Testing Tool / Database Seeder
 *
 * Description: Dedicated database seed command for local/test/staging environments.
 *              Hard-refuses execution in production mode (APP_ENV=production).
 *              Seeds Tenant, Application, API Keys, Admin, 5 realistic test users, and Organization.
 *              Idempotent upsert logic allows safe repeated execution.
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
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	log.Println("🌱 Authn Platform — Database Seeder starting...")

	// 1. Production Execution Guard
	rawEnv := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV")))
	if rawEnv == "" {
		rawEnv = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}

	if rawEnv == "production" {
		log.Println("❌ FATAL: Database seeding is strictly PROHIBITED in production mode (APP_ENV=production). Execution terminated.")
		os.Exit(1)
	}

	// 2. Load Configuration
	cfg, err := config.Load()
	if err != nil {
		log.Printf("⚠️ Config warning: %v. Using local dev configuration defaults.", err)
		cfg = &config.Config{
			DatabaseURL:        "file:authn.db?cache=shared&_fk=1",
			APIKeyPepper:  "dev_pepper_key_32_bytes_long_123456",
			EncryptionKey: "dev_encryption_key_32_bytes_long_12345",
		}
	}

	// 3. Connect to Database via ClientFactory
	driver := "sqlite3"
	if cfg.DatabaseURL != "" && (strings.HasPrefix(cfg.DatabaseURL, "postgres://") || strings.HasPrefix(cfg.DatabaseURL, "postgresql://")) {
		driver = "postgres"
	}

	factory, err := clientfactory.NewClientFactory(driver, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("❌ Failed connecting to database for seeding: %v", err)
	}
	defer factory.Close()

	ctx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(ctx, "tnt_default", "")
	authRepo := auth.NewRepository(factory)
	apiKeyRepo := apikey.NewRepository(factory)

	// 4. Seed Tenant & Application
	tenantID := "tnt_default"
	appID := "app_test123"

	if err := authRepo.EnsureTenantExists(ctx, tenantID); err != nil {
		log.Fatalf("failed seeding tenant: %v", err)
	}
	if err := authRepo.EnsureDefaultApplicationExists(ctx, appID, tenantID, []string{"http://localhost:3000/callback"}); err != nil {
		log.Fatalf("failed seeding application: %v", err)
	}

	// 5. Seed API Keys (Publishable Key & Secret Key)
	pkKey := "pk_test_demo12345678901234567890123456789012"
	skKey := "sk_test_demo12345678901234567890123456789012"

	_ = apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_pk_demo123", appID, pkKey, cfg.APIKeyPepper)
	_ = apiKeyRepo.EnsureDefaultApiKeyExists(ctx, "key_sk_demo123", appID, skKey, cfg.APIKeyPepper)

	// 6. Seed System Roles
	rolesToSeed := []struct {
		ID          string
		Name        string
		Slug        string
		Permissions []string
	}{
		{"role_tenant_admin", "Tenant Administrator", "tenant_admin", []string{"*"}},
		{"role_org_admin", "Organization Administrator", "org_admin", []string{"orgs:*", "members:*"}},
		{"role_editor", "Editor", "editor", []string{"orgs:read", "members:read", "content:write"}},
		{"role_viewer", "Viewer", "viewer", []string{"orgs:read", "members:read"}},
	}

	roleMap := make(map[string]*ent.Role)
	for _, r := range rolesToSeed {
		existing, err := client.Role.Query().
			Where(role.TenantID(tenantID), role.Slug(r.Slug)).
			Only(ctx)
		if err != nil {
			created, err := client.Role.Create().
				SetID(r.ID).
				SetTenantID(tenantID).
				SetName(r.Name).
				SetSlug(r.Slug).
				SetDescription("System role for " + r.Name).
				SetIsSystemRole(true).
				Save(ctx)
			if err != nil {
				log.Printf("⚠️ Failed seeding role %s: %v", r.Slug, err)
			} else {
				roleMap[r.Slug] = created
			}
		} else {
			roleMap[r.Slug] = existing
		}
	}

	// 7. Seed Admin User & 5 Regular Users (Idempotent Upsert)
	type UserSeedSpec struct {
		ID            string
		Email         string
		Password      string
		EmailVerified bool
		RoleSlug      string
		SpecialState  string
		SetupFunc     func(u *ent.User)
	}

	userSpecs := []UserSeedSpec{
		{
			ID:            "usr_admin_001",
			Email:         "admin@authn.local",
			Password:      "AdminPass123!",
			EmailVerified: true,
			RoleSlug:      "tenant_admin",
			SpecialState:  "System Tenant Admin",
			SetupFunc: func(u *ent.User) {
				adminRole := roleMap["tenant_admin"]
				if adminRole != nil {
					isAssigned, _ := client.UserRole.Query().
						Where(userrole.UserID(u.ID), userrole.RoleID(adminRole.ID)).
						Exist(ctx)
					if !isAssigned {
						_, _ = client.UserRole.Create().
							SetID("ur_admin_001").
							SetUserID(u.ID).
							SetRoleID(adminRole.ID).
							Save(ctx)
					}
				}
			},
		},
		{
			ID:            "usr_totp_002",
			Email:         "user.totp@authn.local",
			Password:      "UserPass123!",
			EmailVerified: true,
			RoleSlug:      "viewer",
			SpecialState:  "TOTP 2FA Enrolled (Secret: JBSWY3DPEHPK3PXP)",
			SetupFunc: func(u *ent.User) {
				hasTOTP, _ := client.TwoFactorMethod.Query().
					Where(twofactormethod.UserID(u.ID), twofactormethod.TypeEQ(twofactormethod.TypeTotp)).
					Exist(ctx)
				if !hasTOTP {
					_, _ = client.TwoFactorMethod.Create().
						SetID("tfm_totp_spec").
						SetUserID(u.ID).
						SetType(twofactormethod.TypeTotp).
						SetName("Authenticator App").
						SetSecretEncrypted("JBSWY3DPEHPK3PXP").
						SetIsEnabled(true).
						Save(ctx)
				}
			},
		},
		{
			ID:            "usr_unverified_003",
			Email:         "user.unverified@authn.local",
			Password:      "UserPass123!",
			EmailVerified: false,
			RoleSlug:      "viewer",
			SpecialState:  "Email Unverified (Pending Verification)",
		},
		{
			ID:            "usr_orgmember_004",
			Email:         "user.orgmember@authn.local",
			Password:      "UserPass123!",
			EmailVerified: true,
			RoleSlug:      "editor",
			SpecialState:  "Organization Member (Acme Corp / Editor)",
		},
		{
			ID:            "usr_guardians_005",
			Email:         "user.guardians@authn.local",
			Password:      "UserPass123!",
			EmailVerified: true,
			RoleSlug:      "viewer",
			SpecialState:  "Account Recovery Guardians Configured",
			SetupFunc: func(u *ent.User) {
				gEmail := "guardian@authn.local"
				gUser, err := client.User.Query().Where(user.Email(gEmail)).Only(ctx)
				if err != nil {
					hash, _ := crypto.HashPasswordArgon2id("UserPass123!")
					gUser, _ = client.User.Create().
						SetID("usr_guardian_006").
						SetTenantID(tenantID).
						SetEmail(gEmail).
						SetPasswordHash(hash).
						SetEmailVerified(true).
						Save(ctx)
				}
				if gUser != nil {
					hasContact, _ := client.RecoveryContact.Query().
						Where(recoverycontact.UserID(u.ID), recoverycontact.GuardianEmail(gEmail)).
						Exist(ctx)
					if !hasContact {
						_, _ = client.RecoveryContact.Create().
							SetID("rec_c_" + uuid.New().String()[:8]).
							SetUserID(u.ID).
							SetGuardianEmail(gEmail).
							SetGuardianName("Trusted Guardian").
							SetShareIndex(1).
							SetShareHash("mock_share_hash_12345678901234567890123456789012").
							SetStatus("active").
							Save(ctx)
					}
				}
			},
		},
		{
			ID:            "usr_vanilla_007",
			Email:         "user.vanilla@authn.local",
			Password:      "UserPass123!",
			EmailVerified: true,
			RoleSlug:      "viewer",
			SpecialState:  "Vanilla / Default Active User",
		},
	}

	seededUsers := make(map[string]*ent.User)

	for _, spec := range userSpecs {
		existing, err := client.User.Query().
			Where(user.TenantID(tenantID), user.Email(spec.Email)).
			Only(ctx)
		if err != nil {
			hash, err := crypto.HashPasswordArgon2id(spec.Password)
			if err != nil {
				log.Fatalf("failed hashing password for %s: %v", spec.Email, err)
			}
			created, err := client.User.Create().
				SetID(spec.ID).
				SetTenantID(tenantID).
				SetEmail(spec.Email).
				SetPasswordHash(hash).
				SetEmailVerified(spec.EmailVerified).
				Save(ctx)
			if err != nil {
				log.Printf("⚠️ Failed seeding user %s: %v", spec.Email, err)
				continue
			}
			existing = created
		}
		seededUsers[spec.Email] = existing

		if spec.SetupFunc != nil {
			spec.SetupFunc(existing)
		}
	}

	// 8. Seed B2B Organization & Memberships
	orgID := "org_acme"
	orgName := "Acme Corp"
	orgSlug := "acme-corp"

	orgObj, err := client.Organization.Query().Where(organization.ID(orgID)).Only(ctx)
	if err != nil {
		orgObj, err = client.Organization.Create().
			SetID(orgID).
			SetTenantID(tenantID).
			SetName(orgName).
			SetSlug(orgSlug).
			Save(ctx)
		if err != nil {
			log.Printf("⚠️ Failed seeding Organization %s: %v", orgID, err)
		}
	}

	if orgObj != nil {
		// Link Admin as org_admin
		adminUser := seededUsers["admin@authn.local"]
		if adminUser != nil {
			isMem, _ := client.OrgMember.Query().
				Where(orgmember.OrganizationID(orgID), orgmember.UserID(adminUser.ID)).
				Exist(ctx)
			if !isMem {
				_, _ = client.OrgMember.Create().
					SetID("mem_admin_acme").
					SetOrganizationID(orgID).
					SetUserID(adminUser.ID).
					SetRoleID("role_org_admin").
					Save(ctx)
			}
		}

		// Link Member as editor
		memUser := seededUsers["user.orgmember@authn.local"]
		if memUser != nil {
			isMem, _ := client.OrgMember.Query().
				Where(orgmember.OrganizationID(orgID), orgmember.UserID(memUser.ID)).
				Exist(ctx)
			if !isMem {
				_, _ = client.OrgMember.Create().
					SetID("mem_user_acme").
					SetOrganizationID(orgID).
					SetUserID(memUser.ID).
					SetRoleID("role_org_editor").
					Save(ctx)
			}
		}

		// Seed Enterprise SAML Connection for Acme Corp
		hasSAML, _ := client.SAMLConnection.Query().
			Where(samlconnection.OrganizationID(orgID)).
			Exist(ctx)
		if !hasSAML {
			_, _ = client.SAMLConnection.Create().
				SetID("saml_acme_corp").
				SetOrganizationID(orgID).
				SetIdpEntityID("https://idp.acme-corp.com/saml/metadata").
				SetIdpSSOURL("https://idp.acme-corp.com/saml/sso").
				SetIdpCertificate("-----BEGIN CERTIFICATE-----\nMIICXzCCAcegAwIBAgIU...\n-----END CERTIFICATE-----").
				SetAllowedDomains([]string{"acme-corp.com"}).
				SetEnforceSSO(true).
				Save(ctx)
		}
	}

	// 9. Display Seeded Summary Output
	fmt.Println("\n================================================================================")
	fmt.Println("🌱 DATABASE SEEDING COMPLETED SUCCESSFULLY (Idempotent Upsert)")
	fmt.Println("================================================================================")
	fmt.Printf("🔑 Publishable Key  : %s\n", pkKey)
	fmt.Printf("🔑 Secret Key       : %s\n", skKey)
	fmt.Printf("🏢 Organization     : %s (ID: %s, Slug: %s)\n", orgName, orgID, orgSlug)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("USERS SEEDED FOR TESTING:")
	fmt.Println("--------------------------------------------------------------------------------")
	for _, spec := range userSpecs {
		fmt.Printf("• %-28s | Password: %-13s | State: %s\n", spec.Email, spec.Password, spec.SpecialState)
	}
	fmt.Println("================================================================================")
}
