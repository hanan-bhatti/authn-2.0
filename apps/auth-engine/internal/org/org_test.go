/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/org_test.go
 * Tier: Automated Testing Layer / Unit & Integration Tests
 *
 * Description: Test suite for B2B organizations and team member invitations (FR-15).
 *              Covers validation bounds, organization CRUD, membership management,
 *              invitation issue/redeem/revoke, metadata size limits, and the
 *              per-organization authorization rules.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/org"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

// setupTestService builds a service over a throwaway SQLite database seeded with
// a tenant and two users, and returns it with a cleanup function.
func setupTestService(t *testing.T) (*org.Service, *clientfactory.ClientFactory, func()) {
	tmpDir, err := os.MkdirTemp("", "org_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db") + "?_fk=1"
	factory, err := clientfactory.NewClientFactory("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to initialize client factory: %v", err)
	}

	ctx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(ctx, "tnt_test", "")
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	_, err = client.Tenant.Create().SetID("tnt_test").SetName("Test Tenant").SetSlug("test-tenant").Save(ctx)
	if err != nil && !ent.IsConstraintError(err) {
		t.Fatalf("failed to seed tenant: %v", err)
	}

	_, err = client.User.Create().
		SetID("usr_creator").
		SetTenantID("tnt_test").
		SetEmail("creator@example.com").
		SetPasswordHash("hash").
		Save(ctx)
	if err != nil && !ent.IsConstraintError(err) {
		t.Fatalf("failed to seed creator user: %v", err)
	}

	_, err = client.User.Create().
		SetID("usr_invitee").
		SetTenantID("tnt_test").
		SetEmail("invitee@example.com").
		SetPasswordHash("hash").
		Save(ctx)
	if err != nil && !ent.IsConstraintError(err) {
		t.Fatalf("failed to seed invitee user: %v", err)
	}

	svc := org.NewService(factory, nil)

	cleanup := func() {
		_ = factory.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return svc, factory, cleanup
}

// TestOrgValidation checks the request-level bounds on name, slug and logo URL.
func TestOrgValidation(t *testing.T) {
	req := org.CreateOrgRequest{Name: "A"} // Too short
	if err := req.Validate(); err == nil {
		t.Errorf("expected error for short name, got nil")
	}

	req = org.CreateOrgRequest{Name: "Valid Name", Slug: "INVALID SLUG!"}
	if err := req.Validate(); err == nil {
		t.Errorf("expected error for invalid slug format, got nil")
	}

	req = org.CreateOrgRequest{Name: "Valid Name", LogoURL: "not-a-url"}
	if err := req.Validate(); err == nil {
		t.Errorf("expected error for invalid logo URL, got nil")
	}

	req = org.CreateOrgRequest{Name: "Valid Workspace", Slug: "valid-slug", LogoURL: "https://example.com/logo.png"}
	if err := req.Validate(); err != nil {
		t.Errorf("unexpected error for valid payload: %v", err)
	}
}

// TestOrganizationLifecycle walks create, duplicate-slug rejection, read, update
// and delete as the creator, who is auto-assigned org_admin.
func TestOrganizationLifecycle(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	created, err := svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name:    "Acme Engineering",
		Slug:    "acme-eng",
		LogoURL: "https://acme.com/logo.png",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}
	if created.ID == "" || created.Slug != "acme-eng" {
		t.Errorf("unexpected created org payload: %+v", created)
	}

	_, err = svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name: "Acme Engineering Duplicate",
		Slug: "acme-eng",
	}, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Errorf("expected duplicate slug error, got nil")
	}

	fetched, err := svc.GetOrganization(ctx, "tnt_test", created.ID, "usr_creator", false)
	if err != nil {
		t.Fatalf("failed to get org: %v", err)
	}
	if fetched.Name != "Acme Engineering" {
		t.Errorf("expected name 'Acme Engineering', got '%s'", fetched.Name)
	}

	newName := "Acme Corp Global"
	updated, err := svc.UpdateOrganization(ctx, "tnt_test", "usr_creator", created.ID, org.UpdateOrgRequest{
		Name: &newName,
	}, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to update org: %v", err)
	}
	if updated.Name != "Acme Corp Global" {
		t.Errorf("expected updated name 'Acme Corp Global', got '%s'", updated.Name)
	}

	err = svc.DeleteOrganization(ctx, "tnt_test", "usr_creator", created.ID, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to delete org: %v", err)
	}

	_, err = svc.GetOrganization(ctx, "tnt_test", created.ID, "usr_creator", false)
	if err == nil {
		t.Errorf("expected NotFound error after deletion, got nil")
	}
}

// TestCreateOrganizationWithNoActorEnrollsNobody covers the tenant-admin tier,
// which names no actor: the caller is a key or a console operator rather than a
// member of the organization being created.
//
// The organization is created and nobody is enrolled in it. An actor that is not a
// user would fail the membership foreign key, so a placeholder here would cost a
// refused insert on every administrative create and leave the same empty
// membership behind.
func TestCreateOrganizationWithNoActorEnrollsNobody(t *testing.T) {
	svc, factory, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	created, err := svc.CreateOrganization(ctx, "tnt_test", "", org.CreateOrgRequest{
		Name: "Admin Provisioned",
		Slug: "admin-provisioned",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create org with no actor: %v", err)
	}

	members, err := factory.GetClient(ctx, "tnt_test", "").OrgMember.Query().
		Where(orgmember.OrganizationID(created.ID)).
		Count(ctx)
	if err != nil {
		t.Fatalf("failed to count members: %v", err)
	}
	if members != 0 {
		t.Errorf("expected 0 members on an admin-created org, got %d", members)
	}
}

// TestCreateOrganizationStampsTheEnvironmentFromTheContext pins the one branch the
// HTTP tests cannot reach: what a context naming no environment produces.
//
// A scoped caller's workspace has to land in the environment that caller reads, or
// it is unreachable from the moment it is created. A bypass context — provisioning,
// seeding, a migration — names no environment, and rather than guess one the create
// leaves the field to its schema default, so a seeded workspace lands in test and
// never silently in live.
func TestCreateOrganizationStampsTheEnvironmentFromTheContext(t *testing.T) {
	svc, factory, cleanup := setupTestService(t)
	defer cleanup()

	bypass := privacy.NewBypassContext(context.Background())

	cases := []struct {
		name string
		ctx  context.Context
		slug string
		want organization.Environment
	}{
		{"test scope", privacy.NewContext(context.Background(), "tnt_test", "", "test"), "scoped-test", organization.EnvironmentTest},
		{"live scope", privacy.NewContext(context.Background(), "tnt_test", "", "live"), "scoped-live", organization.EnvironmentLive},
		{"bypass", bypass, "unscoped", organization.EnvironmentTest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			created, err := svc.CreateOrganization(tc.ctx, "tnt_test", "", org.CreateOrgRequest{
				Name: "Scope " + tc.slug,
				Slug: tc.slug,
			}, "127.0.0.1", "TestAgent")
			if err != nil {
				t.Fatalf("failed to create org under a %s context: %v", tc.name, err)
			}
			if created.Environment != string(tc.want) {
				t.Errorf("response reports environment %q, want %q", created.Environment, tc.want)
			}

			stored, err := factory.GetClient(bypass, "tnt_test", "").Organization.Get(bypass, created.ID)
			if err != nil {
				t.Fatalf("failed to re-read the stored org: %v", err)
			}
			if stored.Environment != tc.want {
				t.Errorf("stored environment is %q, want %q", stored.Environment, tc.want)
			}
		})
	}
}

// TestSlugUniquenessIsCheckedInTheTargetEnvironment covers the gap between the
// service's own check and the unique index behind it.
//
// The check is a query, and under a scoped context the interceptor narrows it to
// one environment for free. Under a bypass it narrows nothing, so a check written
// as "does this tenant hold the slug" would see the other environment's workspaces
// and refuse a slug the insert would have accepted. The two have to bound the same
// set, or seeding a test workspace fails because production already uses the name.
func TestSlugUniquenessIsCheckedInTheTargetEnvironment(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	defer cleanup()

	live := privacy.NewContext(context.Background(), "tnt_test", "", "live")
	bypass := privacy.NewBypassContext(context.Background())

	if _, err := svc.CreateOrganization(live, "tnt_test", "", org.CreateOrgRequest{
		Name: "Acme Production",
		Slug: "acme",
	}, "127.0.0.1", "TestAgent"); err != nil {
		t.Fatalf("failed to create the live workspace: %v", err)
	}

	// A bypass create lands in test, where the slug is free.
	created, err := svc.CreateOrganization(bypass, "tnt_test", "", org.CreateOrgRequest{
		Name: "Acme Rehearsal",
		Slug: "acme",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("a live workspace named acme blocked a test one: %v", err)
	}
	if created.Environment != string(organization.EnvironmentTest) {
		t.Fatalf("bypass create landed in %q, want %q", created.Environment, organization.EnvironmentTest)
	}

	// Within that environment it is now taken, and the check still says so.
	if _, err := svc.CreateOrganization(bypass, "tnt_test", "", org.CreateOrgRequest{
		Name: "Acme Rehearsal Again",
		Slug: "acme",
	}, "127.0.0.1", "TestAgent"); !errors.Is(err, org.ErrOrgSlugExists) {
		t.Errorf("expected ErrOrgSlugExists on a repeat within one environment, got: %v", err)
	}

	// A rename is bounded by the environment of the row being renamed, not by the
	// tenant, so the live workspace's slug is available to the test one.
	t.Run("a rename is bounded the same way", func(t *testing.T) {
		other, err := svc.CreateOrganization(bypass, "tnt_test", "", org.CreateOrgRequest{
			Name: "Acme Staging",
			Slug: "acme-staging",
		}, "127.0.0.1", "TestAgent")
		if err != nil {
			t.Fatalf("failed to create the workspace to rename: %v", err)
		}

		taken := "acme"
		if _, err := svc.UpdateOrganization(bypass, "tnt_test", "", other.ID, org.UpdateOrgRequest{
			Slug: &taken,
		}, true, "127.0.0.1", "TestAgent"); !errors.Is(err, org.ErrOrgSlugExists) {
			t.Errorf("expected ErrOrgSlugExists renaming onto a slug held in the same environment, got: %v", err)
		}

		free := "acme-production-name"
		liveHeld, err := svc.CreateOrganization(live, "tnt_test", "", org.CreateOrgRequest{
			Name: "Acme Holds This",
			Slug: free,
		}, "127.0.0.1", "TestAgent")
		if err != nil {
			t.Fatalf("failed to create the live holder: %v", err)
		}

		updated, err := svc.UpdateOrganization(bypass, "tnt_test", "", other.ID, org.UpdateOrgRequest{
			Slug: &free,
		}, true, "127.0.0.1", "TestAgent")
		if err != nil {
			t.Fatalf("a live workspace's slug blocked a test rename: %v", err)
		}
		if updated.Slug != free {
			t.Errorf("rename stored slug %q, want %q", updated.Slug, free)
		}
		if updated.ID == liveHeld.ID {
			t.Fatalf("the rename addressed the live workspace instead of the test one")
		}
	})
}

// TestMemberManagement covers adding, listing, re-roling and removing a member.
func TestMemberManagement(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	orgObj, err := svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name: "Member Test Org",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	mem, err := svc.AddMember(ctx, "tnt_test", "usr_creator", orgObj.ID, org.AddMemberRequest{
		UserID: "usr_invitee",
		RoleID: "editor",
	}, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to add member: %v", err)
	}
	if mem.UserID != "usr_invitee" {
		t.Errorf("unexpected member user ID: %s", mem.UserID)
	}

	members, err := svc.ListOrgMembers(ctx, "tnt_test", orgObj.ID, "usr_creator", false, 10, 0)
	if err != nil {
		t.Fatalf("failed to list members: %v", err)
	}
	if len(members) < 2 {
		t.Errorf("expected at least 2 members (creator + invitee), got %d", len(members))
	}

	updatedMem, err := svc.UpdateMemberRole(ctx, "tnt_test", "usr_creator", orgObj.ID, "usr_invitee", org.UpdateMemberRoleRequest{
		RoleID: "org_admin",
	}, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to update member role: %v", err)
	}
	if updatedMem == nil {
		t.Fatalf("updated member response is nil")
	}

	err = svc.RemoveMember(ctx, "tnt_test", "usr_creator", orgObj.ID, "usr_invitee", false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to remove member: %v", err)
	}
}

// TestInvitationFlow covers issuing, listing and redeeming an invitation, and
// confirms a token is single-use.
func TestInvitationFlow(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	orgObj, err := svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name: "Invitation Test Org",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	inv, err := svc.CreateInvitation(ctx, "tnt_test", "usr_creator", orgObj.ID, org.CreateInvitationRequest{
		Email:      "invitee@example.com",
		RoleID:     "editor",
		ExpiresHrs: 24,
	}, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create invitation: %v", err)
	}
	if inv.InvitationToken == "" || inv.Status != "pending" {
		t.Errorf("unexpected invitation response: %+v", inv)
	}

	invs, err := svc.ListPendingInvitations(ctx, "tnt_test", orgObj.ID, "usr_creator", false, 10, 0)
	if err != nil {
		t.Fatalf("failed to list pending invitations: %v", err)
	}
	if len(invs) != 1 {
		t.Errorf("expected 1 pending invitation, got %d", len(invs))
	}

	acceptedMem, err := svc.AcceptInvitation(ctx, "tnt_test", "usr_invitee", org.AcceptInvitationRequest{
		InvitationToken: inv.InvitationToken,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to accept invitation: %v", err)
	}
	if acceptedMem.UserID != "usr_invitee" {
		t.Errorf("expected accepted member user_id 'usr_invitee', got '%s'", acceptedMem.UserID)
	}

	_, err = svc.AcceptInvitation(ctx, "tnt_test", "usr_invitee", org.AcceptInvitationRequest{
		InvitationToken: inv.InvitationToken,
	}, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Errorf("expected error when accepting already accepted invitation, got nil")
	}
}

// TestRevokeInvitation confirms a revoked invitation can no longer be redeemed.
func TestRevokeInvitation(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	orgObj, err := svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name: "Revoke Test Org",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	inv, err := svc.CreateInvitation(ctx, "tnt_test", "usr_creator", orgObj.ID, org.CreateInvitationRequest{
		Email:  "revoke@example.com",
		RoleID: "viewer",
	}, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create invitation: %v", err)
	}

	err = svc.RevokeInvitation(ctx, "tnt_test", "usr_creator", orgObj.ID, inv.ID, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to revoke invitation: %v", err)
	}

	_, err = svc.AcceptInvitation(ctx, "tnt_test", "usr_invitee", org.AcceptInvitationRequest{
		InvitationToken: inv.InvitationToken,
	}, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Errorf("expected error accepting revoked invitation, got nil")
	}
}

// TestOrgMetadataSizeLimit verifies the serialized-JSON cap on organization
// metadata is enforced on both create and update, and that metadata under the cap
// is stored unchanged.
func TestOrgMetadataSizeLimit(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	// A single value longer than the cap guarantees the encoded object exceeds it.
	oversized := map[string]interface{}{
		"blob": strings.Repeat("a", org.MaxMetadataSizeBytes+1),
	}
	normal := map[string]interface{}{
		"team":  "platform",
		"tier":  "enterprise",
		"seats": 25,
	}

	// 1. Oversized metadata is rejected on create.
	_, err := svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name:     "Oversized Metadata Org",
		Slug:     "oversized-meta",
		Metadata: oversized,
	}, "127.0.0.1", "TestAgent")
	if !errors.Is(err, org.ErrMetadataTooLarge) {
		t.Fatalf("expected ErrMetadataTooLarge on create, got: %v", err)
	}

	// 2. Normal metadata is accepted on create and round-trips intact.
	created, err := svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name:     "Normal Metadata Org",
		Slug:     "normal-meta",
		Metadata: normal,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("expected normal metadata to be accepted on create, got: %v", err)
	}
	if created.Metadata["team"] != "platform" {
		t.Errorf("expected metadata to round-trip, got: %+v", created.Metadata)
	}

	// 3. Oversized metadata is rejected on update.
	_, err = svc.UpdateOrganization(ctx, "tnt_test", "usr_creator", created.ID, org.UpdateOrgRequest{
		Metadata: oversized,
	}, false, "127.0.0.1", "TestAgent")
	if !errors.Is(err, org.ErrMetadataTooLarge) {
		t.Fatalf("expected ErrMetadataTooLarge on update, got: %v", err)
	}

	// A rejected update must leave the stored metadata untouched.
	unchanged, err := svc.GetOrganization(ctx, "tnt_test", created.ID, "usr_creator", false)
	if err != nil {
		t.Fatalf("failed to re-read org after rejected update: %v", err)
	}
	if unchanged.Metadata["team"] != "platform" {
		t.Errorf("rejected update must not modify stored metadata, got: %+v", unchanged.Metadata)
	}

	// 4. Normal metadata is accepted on update.
	replacement := map[string]interface{}{"team": "infrastructure"}
	updated, err := svc.UpdateOrganization(ctx, "tnt_test", "usr_creator", created.ID, org.UpdateOrgRequest{
		Metadata: replacement,
	}, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("expected normal metadata to be accepted on update, got: %v", err)
	}
	if updated.Metadata["team"] != "infrastructure" {
		t.Errorf("expected updated metadata to be stored, got: %+v", updated.Metadata)
	}
}

// TestAuthorizationEnforcement pins the per-organization rules: non-members are
// denied reads, non-admin members are denied mutations, an unauthenticated caller
// is denied outright, and the tenant-admin tier bypasses both checks.
func TestAuthorizationEnforcement(t *testing.T) {
	svc, factory, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	// Creator makes an org and is auto-assigned org_admin.
	orgObj, err := svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name: "Authz Test Org",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	// Seed a stranger user who is NOT a member of the org.
	client := factory.GetClient(ctx, "tnt_test", "")
	_, err = client.User.Create().
		SetID("usr_stranger").
		SetTenantID("tnt_test").
		SetEmail("stranger@example.com").
		SetPasswordHash("hash").
		Save(ctx)
	if err != nil && !ent.IsConstraintError(err) {
		t.Fatalf("failed to seed stranger: %v", err)
	}

	// 1. Non-member is DENIED read (GetOrganization).
	if _, err := svc.GetOrganization(ctx, "tnt_test", orgObj.ID, "usr_stranger", false); err == nil {
		t.Errorf("SECURITY: expected non-member to be denied GetOrganization, got nil error")
	}

	// 2. Non-member is DENIED read (ListOrgMembers).
	if _, err := svc.ListOrgMembers(ctx, "tnt_test", orgObj.ID, "usr_stranger", false, 10, 0); err == nil {
		t.Errorf("SECURITY: expected non-member to be denied ListOrgMembers, got nil error")
	}

	// 3. Empty actorID (unauthenticated) is DENIED.
	if _, err := svc.GetOrganization(ctx, "tnt_test", orgObj.ID, "", false); err == nil {
		t.Errorf("SECURITY: expected empty actorID to be denied GetOrganization, got nil error")
	}

	// 4. Non-member is DENIED mutation (DeleteOrganization).
	if err := svc.DeleteOrganization(ctx, "tnt_test", "usr_stranger", orgObj.ID, false, "127.0.0.1", "TestAgent"); err == nil {
		t.Errorf("SECURITY: expected non-member to be denied DeleteOrganization, got nil error")
	}

	// 5. Add a member with a NON-admin role (editor, no orgs:*/members:*).
	//    editor has no Permission edge rows here and slug != org_admin, so it must be denied mutations.
	if _, err := svc.AddMember(ctx, "tnt_test", "usr_creator", orgObj.ID, org.AddMemberRequest{
		UserID: "usr_stranger",
		RoleID: "editor",
	}, false, "127.0.0.1", "TestAgent"); err != nil {
		t.Fatalf("setup: creator failed to add editor member: %v", err)
	}

	// 5a. The editor CAN read (is now a member).
	if _, err := svc.GetOrganization(ctx, "tnt_test", orgObj.ID, "usr_stranger", false); err != nil {
		t.Errorf("expected editor member to be allowed GetOrganization, got: %v", err)
	}

	// 5b. But the editor CANNOT mutate (not org_admin).
	newName := "Editor Should Not Rename This"
	if _, err := svc.UpdateOrganization(ctx, "tnt_test", "usr_stranger", orgObj.ID, org.UpdateOrgRequest{
		Name: &newName,
	}, false, "127.0.0.1", "TestAgent"); err == nil {
		t.Errorf("SECURITY: expected non-admin editor to be denied UpdateOrganization, got nil error")
	}

	// 6. Admin-tier bypass (isAdmin=true) succeeds even with an empty actorID —
	//    this is the tenant-admin / sk_ path and must keep working.
	if _, err := svc.GetOrganization(ctx, "tnt_test", orgObj.ID, "", true); err != nil {
		t.Errorf("expected admin-tier bypass to be allowed GetOrganization, got: %v", err)
	}
	if err := svc.DeleteOrganization(ctx, "tnt_test", "", orgObj.ID, true, "127.0.0.1", "TestAgent"); err != nil {
		t.Errorf("expected admin-tier bypass to be allowed DeleteOrganization, got: %v", err)
	}
}
