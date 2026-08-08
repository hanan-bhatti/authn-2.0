/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Core business logic implementation for B2B Organizations and Org Member
 *              management. Handles CRUD operations, slug generation, transaction isolation,
 *              audit logging, and real-time webhook event dispatching.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

var (
	nonAlphanumericRegex = regexp.MustCompile(`[^a-z0-9]+`)
)

type WebhookDispatcher interface {
	Dispatch(tenantID, eventType string, data map[string]interface{})
}

type Service struct {
	factory    *clientfactory.ClientFactory
	dispatcher WebhookDispatcher
}

func NewService(factory *clientfactory.ClientFactory, dispatcher WebhookDispatcher) *Service {
	return &Service{
		factory:    factory,
		dispatcher: dispatcher,
	}
}

// authzCheckMember verifies that actorID is an active member of orgID.
// Returns the membership record if authorized, or an error if not.
// This is the base authorization check for any org-scoped operation.
func (s *Service) authzCheckMember(ctx context.Context, client *ent.Client, actorID, orgID string) (*ent.OrgMember, error) {
	if actorID == "" {
		return nil, ErrNotAMember
	}

	membership, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(orgID), orgmember.UserID(actorID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotAMember
		}
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	return membership, nil
}

// authzRequireOrgAdmin verifies that actorID holds the org_admin role (or equivalent admin permissions).
// Returns the membership record if authorized, or an error if not.
// This is the required check for all mutating org operations (update, delete, add/remove members, invitations).
func (s *Service) authzRequireOrgAdmin(ctx context.Context, client *ent.Client, actorID, orgID string) (*ent.OrgMember, error) {
	membership, err := s.authzCheckMember(ctx, client, actorID, orgID)
	if err != nil {
		return nil, err
	}

	// Load the role (with its permission edge) to check permissions
	roleRecord, err := client.Role.Query().
		Where(role.ID(membership.RoleID)).
		WithPermissions().
		Only(ctx)
	if err != nil {
		// A member whose role can't be resolved cannot be granted admin rights.
		return nil, ErrForbidden
	}

	// org_admin slug OR permission action containing "orgs:*" or "members:*" OR "*"
	if roleRecord.Slug == "org_admin" {
		return membership, nil
	}
	for _, perm := range roleRecord.Edges.Permissions {
		if perm.Action == "*" || perm.Action == "orgs:*" || perm.Action == "members:*" {
			return membership, nil
		}
	}

	return nil, ErrForbidden
}

// Slugify generates a clean URL-friendly slug from an input string.
func Slugify(input string) string {
	cleaned := strings.ToLower(strings.TrimSpace(input))
	slug := nonAlphanumericRegex.ReplaceAllString(cleaned, "-")
	return strings.Trim(slug, "-")
}

// ensureDefaultRole fetches or creates a default org role (e.g. org_admin, editor, viewer).
func (s *Service) ensureDefaultRole(ctx context.Context, client *ent.Client, tenantID, roleSlug, roleName string) (*ent.Role, error) {
	r, err := client.Role.Query().
		Where(role.TenantID(tenantID), role.Slug(roleSlug)).
		Only(ctx)
	if err == nil {
		return r, nil
	}

	// Try querying by ID if roleSlug looks like a role ID
	r, err = client.Role.Query().
		Where(role.TenantID(tenantID), role.ID(roleSlug)).
		Only(ctx)
	if err == nil {
		return r, nil
	}

	// Create fallback default role
	roleID := fmt.Sprintf("role_%s", uuid.New().String()[:12])
	return client.Role.Create().
		SetID(roleID).
		SetTenantID(tenantID).
		SetName(roleName).
		SetSlug(roleSlug).
		SetDescription(fmt.Sprintf("Default %s role", roleName)).
		Save(ctx)
}

// CreateOrganization creates a new B2B Organization workspace and auto-assigns the creator as org_admin.
func (s *Service) CreateOrganization(ctx context.Context, tenantID, actorID string, req CreateOrgRequest, ip, userAgent string) (*OrgResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	if req.Slug == "" {
		req.Slug = Slugify(req.Name)
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Check for existing slug in tenant
	exists, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.Slug(req.Slug)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug uniqueness: %w", err)
	}
	if exists {
		return nil, ErrOrgSlugExists
	}

	orgID := fmt.Sprintf("org_%s", uuid.New().String()[:12])
	memID := fmt.Sprintf("mem_%s", uuid.New().String()[:12])

	// Ensure org_admin role exists
	orgAdminRole, err := s.ensureDefaultRole(ctx, client, tenantID, "org_admin", "Organization Admin")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve org_admin role: %w", err)
	}

	// Create Organization entity
	builder := client.Organization.Create().
		SetID(orgID).
		SetTenantID(tenantID).
		SetName(req.Name).
		SetSlug(req.Slug)

	if req.LogoURL != "" {
		builder.SetLogoURL(req.LogoURL)
	}
	if req.Metadata != nil {
		builder.SetMetadata(req.Metadata)
	}

	createdOrg, err := builder.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	// Auto-assign creator as member if actorID is specified
	if actorID != "" {
		_, err = client.OrgMember.Create().
			SetID(memID).
			SetOrganizationID(orgID).
			SetUserID(actorID).
			SetRoleID(orgAdminRole.ID).
			SetAssignedByUserID(actorID).
			Save(ctx)
		if err != nil {
			// Non-fatal if actor user doesn't exist, but log error
			fmt.Printf("[Org Service] Warning: failed to auto-assign creator membership: %v\n", err)
		}
	}

	// Log Audit Trail
	s.logAudit(ctx, tenantID, actorID, "org.created", "organization", orgID, map[string]interface{}{
		"name": req.Name,
		"slug": req.Slug,
	}, ip, userAgent)

	// Dispatch Webhook
	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.created", map[string]interface{}{
			"org_id":     orgID,
			"name":       req.Name,
			"slug":       req.Slug,
			"creator_id": actorID,
		})
	}

	return s.toOrgResponse(createdOrg), nil
}

// GetOrganization fetches organization details by ID.
// Authorization: caller must be an active member (C2), OR hold admin_auth_method privilege.
func (s *Service) GetOrganization(ctx context.Context, tenantID, orgID string, actorID string, isAdmin bool) (*OrgResponse, error) {
	client := s.factory.GetClient(ctx, tenantID, "")

	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("failed to query organization: %w", err)
	}

	// Authorization check: tenant-admin tier bypasses membership requirement
	if !isAdmin {
		_, err := s.authzCheckMember(ctx, client, actorID, orgID)
		if err != nil {
			return nil, err
		}
	}

	return s.toOrgResponse(o), nil
}

// ListOrganizationsForUser retrieves all organizations a user is a member of.
func (s *Service) ListOrganizationsForUser(ctx context.Context, tenantID, userID string, limit, offset int) ([]*OrgResponse, error) {
	if limit <= 0 {
		limit = DefaultPaginationLimit
	}
	if limit > MaxPaginationLimit {
		limit = MaxPaginationLimit
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	memberships, err := client.OrgMember.Query().
		Where(orgmember.UserID(userID)).
		WithOrganization().
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query user memberships: %w", err)
	}

	responses := make([]*OrgResponse, 0, len(memberships))
	for _, m := range memberships {
		if m.Edges.Organization != nil && m.Edges.Organization.TenantID == tenantID {
			responses = append(responses, s.toOrgResponse(m.Edges.Organization))
		}
	}

	return responses, nil
}

// ListOrganizationsForTenant retrieves all organizations under a tenant.
func (s *Service) ListOrganizationsForTenant(ctx context.Context, tenantID string, limit, offset int) ([]*OrgResponse, error) {
	if limit <= 0 {
		limit = DefaultPaginationLimit
	}
	if limit > MaxPaginationLimit {
		limit = MaxPaginationLimit
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	orgs, err := client.Organization.Query().
		Where(organization.TenantID(tenantID)).
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query tenant organizations: %w", err)
	}

	responses := make([]*OrgResponse, len(orgs))
	for i, o := range orgs {
		responses[i] = s.toOrgResponse(o)
	}

	return responses, nil
}

// UpdateOrganization updates organization details.
// Authorization: caller must hold org_admin (C2), OR hold admin_auth_method privilege.
func (s *Service) UpdateOrganization(ctx context.Context, tenantID, actorID, orgID string, req UpdateOrgRequest, isAdmin bool, ip, userAgent string) (*OrgResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("failed to find organization: %w", err)
	}

	// Authorization check: tenant-admin tier bypasses org_admin requirement
	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return nil, err
		}
	}

	updater := o.Update()

	if req.Name != nil {
		updater.SetName(*req.Name)
	}
	if req.Slug != nil && *req.Slug != o.Slug {
		exists, err := client.Organization.Query().
			Where(organization.TenantID(tenantID), organization.Slug(*req.Slug), organization.IDNEQ(orgID)).
			Exist(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to check slug uniqueness: %w", err)
		}
		if exists {
			return nil, ErrOrgSlugExists
		}
		updater.SetSlug(*req.Slug)
	}
	if req.LogoURL != nil {
		updater.SetLogoURL(*req.LogoURL)
	}
	if req.Metadata != nil {
		updater.SetMetadata(req.Metadata)
	}

	updatedOrg, err := updater.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update organization: %w", err)
	}

	// Audit Log & Webhook
	s.logAudit(ctx, tenantID, actorID, "org.updated", "organization", orgID, map[string]interface{}{
		"org_id": orgID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.updated", map[string]interface{}{
			"org_id": orgID,
			"name":   updatedOrg.Name,
			"slug":   updatedOrg.Slug,
		})
	}

	return s.toOrgResponse(updatedOrg), nil
}

// DeleteOrganization removes an organization and all its memberships and invitations.
// Authorization: caller must hold org_admin (C2), OR hold admin_auth_method privilege.
func (s *Service) DeleteOrganization(ctx context.Context, tenantID, actorID, orgID string, isAdmin bool, ip, userAgent string) error {
	client := s.factory.GetClient(ctx, tenantID, "")

	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrOrgNotFound
		}
		return fmt.Errorf("failed to find organization: %w", err)
	}

	// Authorization check: tenant-admin tier bypasses org_admin requirement
	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return err
		}
	}

	// Delete associated members & invitations first
	_, _ = client.OrgMember.Delete().Where(orgmember.OrganizationID(orgID)).Exec(ctx)
	_, _ = client.OrgInvitation.Delete().Where(orginvitation.OrganizationID(orgID)).Exec(ctx)
	// Execute Organization deletion
	if err := client.Organization.DeleteOne(o).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

	// Audit Log & Webhook
	s.logAudit(ctx, tenantID, actorID, "org.deleted", "organization", orgID, map[string]interface{}{
		"org_id": orgID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.deleted", map[string]interface{}{
			"org_id": orgID,
		})
	}

	return nil
}

// ListOrgMembers returns members of an organization.
// Authorization: caller must be an active member (C2), OR hold admin_auth_method privilege.
func (s *Service) ListOrgMembers(ctx context.Context, tenantID, orgID string, actorID string, isAdmin bool, limit, offset int) ([]*OrgMemberResponse, error) {
	if limit <= 0 {
		limit = DefaultPaginationLimit
	}
	if limit > MaxPaginationLimit {
		limit = MaxPaginationLimit
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Verify org exists under tenant
	exists, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Exist(ctx)
	if err != nil || !exists {
		return nil, ErrOrgNotFound
	}

	// Authorization check: tenant-admin tier bypasses membership requirement
	if !isAdmin {
		if _, err := s.authzCheckMember(ctx, client, actorID, orgID); err != nil {
			return nil, err
		}
	}

	members, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(orgID)).
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query organization members: %w", err)
	}

	responses := make([]*OrgMemberResponse, len(members))
	for i, m := range members {
		responses[i] = s.toOrgMemberResponse(m)
	}

	return responses, nil
}

// AddMember adds a user directly to an organization with a specific role.
// Authorization: caller must hold org_admin (C2), OR hold admin_auth_method privilege.
func (s *Service) AddMember(ctx context.Context, tenantID, actorID, orgID string, req AddMemberRequest, isAdmin bool, ip, userAgent string) (*OrgMemberResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Check org existence
	exists, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Exist(ctx)
	if err != nil || !exists {
		return nil, ErrOrgNotFound
	}

	// Authorization check: tenant-admin tier bypasses org_admin requirement
	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return nil, err
		}
	}

	// Check if membership already exists
	alreadyMember, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(orgID), orgmember.UserID(req.UserID)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing membership: %w", err)
	}
	if alreadyMember {
		return nil, ErrMemberAlreadyExists
	}

	// Resolve Role
	targetRole, err := s.ensureDefaultRole(ctx, client, tenantID, req.RoleID, "Member Role")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve role: %w", err)
	}

	memID := fmt.Sprintf("mem_%s", uuid.New().String()[:12])
	builder := client.OrgMember.Create().
		SetID(memID).
		SetOrganizationID(orgID).
		SetUserID(req.UserID).
		SetRoleID(targetRole.ID)

	if actorID != "" {
		builder.SetAssignedByUserID(actorID)
	}

	createdMem, err := builder.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to add organization member: %w", err)
	}

	// Audit Log & Webhook
	s.logAudit(ctx, tenantID, actorID, "org.member_joined", "user", req.UserID, map[string]interface{}{
		"org_id":  orgID,
		"user_id": req.UserID,
		"role_id": targetRole.ID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.member_joined", map[string]interface{}{
			"org_id":  orgID,
			"user_id": req.UserID,
			"role_id": targetRole.ID,
		})
	}

	return s.toOrgMemberResponse(createdMem), nil
}

// UpdateMemberRole updates a member's role within an organization.
// Authorization: caller must hold org_admin (C2), OR hold admin_auth_method privilege.
func (s *Service) UpdateMemberRole(ctx context.Context, tenantID, actorID, orgID, userID string, req UpdateMemberRoleRequest, isAdmin bool, ip, userAgent string) (*OrgMemberResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Authorization check: tenant-admin tier bypasses org_admin requirement
	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return nil, err
		}
	}

	mem, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(orgID), orgmember.UserID(userID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrMemberNotFound
		}
		return nil, fmt.Errorf("failed to query member: %w", err)
	}

	targetRole, err := s.ensureDefaultRole(ctx, client, tenantID, req.RoleID, "Updated Role")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve role: %w", err)
	}

	updater := mem.Update().SetRoleID(targetRole.ID)
	if actorID != "" {
		updater.SetUpdatedByUserID(actorID)
	}

	updatedMem, err := updater.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}

	s.logAudit(ctx, tenantID, actorID, "org.member_role_updated", "user", userID, map[string]interface{}{
		"org_id":  orgID,
		"user_id": userID,
		"role_id": targetRole.ID,
	}, ip, userAgent)

	return s.toOrgMemberResponse(updatedMem), nil
}

// RemoveMember removes a user from an organization.
// Authorization: caller must hold org_admin (C2), OR hold admin_auth_method privilege.
func (s *Service) RemoveMember(ctx context.Context, tenantID, actorID, orgID, userID string, isAdmin bool, ip, userAgent string) error {
	client := s.factory.GetClient(ctx, tenantID, "")

	// Authorization check: tenant-admin tier bypasses org_admin requirement
	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return err
		}
	}

	mem, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(orgID), orgmember.UserID(userID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("failed to query member: %w", err)
	}

	if err := client.OrgMember.DeleteOne(mem).Exec(ctx); err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	// Audit Log & Webhook
	s.logAudit(ctx, tenantID, actorID, "org.member_removed", "user", userID, map[string]interface{}{
		"org_id":  orgID,
		"user_id": userID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.member_removed", map[string]interface{}{
			"org_id":  orgID,
			"user_id": userID,
		})
	}

	return nil
}

// Helpers
func (s *Service) toOrgResponse(o *ent.Organization) *OrgResponse {
	if o == nil {
		return nil
	}
	return &OrgResponse{
		ID:        o.ID,
		TenantID:  o.TenantID,
		Name:      o.Name,
		Slug:      o.Slug,
		LogoURL:   o.LogoURL,
		Metadata:  o.Metadata,
		CreatedAt: o.CreatedAt,
	}
}

func (s *Service) toOrgMemberResponse(m *ent.OrgMember) *OrgMemberResponse {
	if m == nil {
		return nil
	}
	resp := &OrgMemberResponse{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		RoleID:         m.RoleID,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
	}
	if m.AssignedByUserID != nil {
		resp.AssignedByUserID = *m.AssignedByUserID
	}
	return resp
}

func (s *Service) logAudit(ctx context.Context, tenantID, actorID, eventType, targetType, targetID string, metadata map[string]interface{}, ip, userAgent string) {
	client := s.factory.GetClient(ctx, tenantID, "")

	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["target_type"] = targetType
	if targetID != "" {
		metadata["target_id"] = targetID
	}

	logID := fmt.Sprintf("log_%s", uuid.New().String()[:12])

	actorType := auditlog.ActorTypeUser
	if strings.HasPrefix(actorID, "key_") || actorID == "system" {
		actorType = auditlog.ActorTypeAdmin
	}

	builder := client.AuditLog.Create().
		SetID(logID).
		SetTenantID(tenantID).
		SetActorType(actorType).
		SetEventType(eventType).
		SetMetadata(metadata)

	if actorID != "" {
		builder.SetUserID(actorID)
	}
	if ip != "" {
		builder.SetIPAddress(ip)
	}
	if userAgent != "" {
		builder.SetUserAgent(userAgent)
	}

	_, _ = builder.Save(ctx)
}
