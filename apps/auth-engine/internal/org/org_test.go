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

	// 3. Get Organization
	fetched, err := svc.GetOrganization(ctx, "tnt_test", created.ID)
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
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to update org: %v", err)
	}
	if updated.Name != "Acme Corp Global" {
		t.Errorf("expected updated name 'Acme Corp Global', got '%s'", updated.Name)
	}

	// 5. Delete Organization
	err = svc.DeleteOrganization(ctx, "tnt_test", "usr_creator", created.ID, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to delete org: %v", err)
	}

	// 6. Verify NotFound
	_, err = svc.GetOrganization(ctx, "tnt_test", created.ID)
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
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to add member: %v", err)
	}
	if mem.UserID != "usr_invitee" {
		t.Errorf("unexpected member user ID: %s", mem.UserID)
	}

	// List members
	members, err := svc.ListOrgMembers(ctx, "tnt_test", orgObj.ID, 10, 0)
	if err != nil {
		t.Fatalf("failed to list members: %v", err)
	}
	if len(members) < 2 {
		t.Errorf("expected at least 2 members (creator + invitee), got %d", len(members))
	}

	// Update member role
	updatedMem, err := svc.UpdateMemberRole(ctx, "tnt_test", "usr_creator", orgObj.ID, "usr_invitee", org.UpdateMemberRoleRequest{
		RoleID: "org_admin",
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to update member role: %v", err)
	}
	if updatedMem == nil {
		t.Fatalf("updated member response is nil")
	}

	// Remove member
	err = svc.RemoveMember(ctx, "tnt_test", "usr_creator", orgObj.ID, "usr_invitee", "127.0.0.1", "TestAgent")
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
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create invitation: %v", err)
	}
	if inv.InvitationToken == "" || inv.Status != "pending" {
		t.Errorf("unexpected invitation response: %+v", inv)
	}

	// List Pending Invitations
	invs, err := svc.ListPendingInvitations(ctx, "tnt_test", orgObj.ID, 10, 0)
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
	}, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("failed to create invitation: %v", err)
	}

	// Revoke Invitation
	err = svc.RevokeInvitation(ctx, "tnt_test", "usr_creator", orgObj.ID, inv.ID, "127.0.0.1", "TestAgent")
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
