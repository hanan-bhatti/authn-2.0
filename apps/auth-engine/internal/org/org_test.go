/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/org_test.go
 * Tier: Automated Testing Layer / Unit & Integration Tests
 *
 * Description: Comprehensive test suite for B2B Organizations & Team Member Invitations (FR-15).
 *              Verifies validation bounds, CRUD operations, membership management, token redemption,
 *              expiration handling, and error conditions.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/org"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	_ "github.com/mattn/go-sqlite3"
)

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

	// Seed test tenant & user
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

func TestOrganizationLifecycle(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := privacy.NewBypassContext(context.Background())

	// 1. Create Organization
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

	// 2. Duplicate Slug Error
	_, err = svc.CreateOrganization(ctx, "tnt_test", "usr_creator", org.CreateOrgRequest{
		Name: "Acme Engineering Duplicate",
		Slug: "acme-eng",
	}, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Errorf("expected duplicate slug error, got nil")
	}

	// 3. Get Organization (as the creator, who is auto-assigned org_admin — real authz path)
	fetched, err := svc.GetOrganization(ctx, "tnt_test", created.ID, "usr_creator", false)
	if err != nil {
		t.Fatalf("failed to get org: %v", err)
	}
	if fetched.Name != "Acme Engineering" {
		t.Errorf("expected name 'Acme Engineering', got '%s'", fetched.Name)
	}

	// 4. Update Organization
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

	// 5. Delete Organization
	err = svc.DeleteOrganization(ctx, "tnt_test", "usr_creator", created.ID, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to delete org: %v", err)
	}

	// 6. Verify NotFound
	_, err = svc.GetOrganization(ctx, "tnt_test", created.ID, "usr_creator", false)
	if err == nil {
		t.Errorf("expected NotFound error after deletion, got nil")
	}
}

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

	// Add member
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

	// List members
	members, err := svc.ListOrgMembers(ctx, "tnt_test", orgObj.ID, "usr_creator", false, 10, 0)
	if err != nil {
		t.Fatalf("failed to list members: %v", err)
	}
	if len(members) < 2 {
		t.Errorf("expected at least 2 members (creator + invitee), got %d", len(members))
	}

	// Update member role
	updatedMem, err := svc.UpdateMemberRole(ctx, "tnt_test", "usr_creator", orgObj.ID, "usr_invitee", org.UpdateMemberRoleRequest{
		RoleID: "org_admin",
	}, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to update member role: %v", err)
	}
	if updatedMem == nil {
		t.Fatalf("updated member response is nil")
	}

	// Remove member
	err = svc.RemoveMember(ctx, "tnt_test", "usr_creator", orgObj.ID, "usr_invitee", false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to remove member: %v", err)
	}
}

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

	// Create Invitation
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

	// List Pending Invitations
	invs, err := svc.ListPendingInvitations(ctx, "tnt_test", orgObj.ID, "usr_creator", false, 10, 0)
	if err != nil {
		t.Fatalf("failed to list pending invitations: %v", err)
	}
	if len(invs) != 1 {
		t.Errorf("expected 1 pending invitation, got %d", len(invs))
	}

	// Accept Invitation
	acceptedMem, err := svc.AcceptInvitation(ctx, "tnt_test", "usr_invitee", org.AcceptInvitationRequest{
		InvitationToken: inv.InvitationToken,
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to accept invitation: %v", err)
	}
	if acceptedMem.UserID != "usr_invitee" {
		t.Errorf("expected accepted member user_id 'usr_invitee', got '%s'", acceptedMem.UserID)
	}

	// Try accepting again (should fail with ErrInvitationAccepted)
	_, err = svc.AcceptInvitation(ctx, "tnt_test", "usr_invitee", org.AcceptInvitationRequest{
		InvitationToken: inv.InvitationToken,
	}, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Errorf("expected error when accepting already accepted invitation, got nil")
	}
}

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

	// Revoke Invitation
	err = svc.RevokeInvitation(ctx, "tnt_test", "usr_creator", orgObj.ID, inv.ID, false, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to revoke invitation: %v", err)
	}

	// Attempting to accept revoked invitation should fail
	_, err = svc.AcceptInvitation(ctx, "tnt_test", "usr_invitee", org.AcceptInvitationRequest{
		InvitationToken: inv.InvitationToken,
	}, "127.0.0.1", "TestAgent")
	if err == nil {
		t.Errorf("expected error accepting revoked invitation, got nil")
	}
}

// TestAuthorizationEnforcement locks in the C2 fix: non-members are denied reads,
// and non-admin members are denied mutations. The admin-tier bypass (isAdmin=true)
// is verified to still succeed. This is the regression guard for the pk-only vuln.
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

	// 4. Non-member is DENIED mutation (DeleteOrganization) — the original CRITICAL.
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
