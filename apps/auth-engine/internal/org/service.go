/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Business logic for B2B organizations and their memberships. Owns
 *              organization CRUD, slug derivation and uniqueness, the per-organization
 *              authorization checks every mutating path runs, role resolution, audit
 *              logging and webhook dispatch.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

var (
	// nonAlphanumericRegex matches runs of characters that cannot appear in a
	// slug; Slugify collapses each run to a single hyphen.
	nonAlphanumericRegex = regexp.MustCompile(`[^a-z0-9]+`)
)

// WebhookDispatcher publishes organization lifecycle events to tenant webhooks.
type WebhookDispatcher interface {
	// Dispatch queues an event for delivery. It must not block the caller.
	Dispatch(tenantID, eventType string, data map[string]interface{})
}

// Service implements organization and membership domain logic.
type Service struct {
	// factory resolves the ent client for a tenant and environment.
	factory *clientfactory.ClientFactory
	// dispatcher publishes lifecycle events. Nil disables webhooks.
	dispatcher WebhookDispatcher
	// cfg supplies the metadata size cap and default invitation lifetime. It may
	// be nil, in which case the package defaults apply.
	cfg *config.Config
}

// NewService constructs an organization Service. dispatcher may be nil.
//
// cfg is variadic only so existing callers keep compiling; pass it in
// application code. Without it the service falls back to MaxMetadataSizeBytes
// and DefaultInviteExpiryHrs, which match the configuration defaults.
func NewService(factory *clientfactory.ClientFactory, dispatcher WebhookDispatcher, cfg ...*config.Config) *Service {
	s := &Service{
		factory:    factory,
		dispatcher: dispatcher,
	}
	if len(cfg) > 0 {
		s.cfg = cfg[0]
	}
	return s
}

// metadataLimitBytes returns the configured cap on serialized organization
// metadata, or the package default when no configuration was supplied.
func (s *Service) metadataLimitBytes() int {
	if s.cfg != nil && s.cfg.OrgMetadataMaxBytes > 0 {
		return s.cfg.OrgMetadataMaxBytes
	}
	return MaxMetadataSizeBytes
}

// invitationTTL returns the configured default invitation lifetime, or the
// package default when no configuration was supplied.
func (s *Service) invitationTTL() time.Duration {
	if s.cfg != nil && s.cfg.InvitationTTL > 0 {
		return s.cfg.InvitationTTL
	}
	return time.Duration(DefaultInviteExpiryHrs) * time.Hour
}

// validateMetadataSize reports ErrMetadataTooLarge when metadata's serialized
// JSON exceeds MaxMetadataSizeBytes. Nil metadata is always accepted.
//
// The encoded length is what matters, not the number of keys: the stored column
// holds the JSON encoding, so that is the size the cap has to bound. An
// unencodable value is rejected here rather than surfacing later as a database
// failure.
func (s *Service) validateMetadataSize(metadata map[string]interface{}) error {
	if metadata == nil {
		return nil
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to encode organization metadata: %w", err)
	}
	if len(encoded) > s.metadataLimitBytes() {
		return ErrMetadataTooLarge
	}

	return nil
}

// authzCheckMember verifies that actorID is a member of orgID and returns the
// membership.
//
// This is the base check for every organization-scoped read. An empty actorID is
// refused outright, so an unauthenticated request cannot pass by supplying no
// identity. Returns ErrNotAMember when there is no membership.
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

// authzRequireOrgAdmin verifies that actorID holds organization-admin rights over
// orgID and returns the membership.
//
// This is the required check for every mutating operation: update, delete,
// member changes and invitations. Admin rights come from the org_admin role slug
// or from a role holding a namespace-wide grant over the organization surface.
// A whole-namespace grant is deliberately required rather than a single matching
// permission: a role granted only "orgs:write" is meant to edit organization
// fields, and treating that as admin would also hand it member removal and
// organization deletion. A member whose role cannot be resolved gets no admin
// rights. Returns ErrNotAMember or ErrForbidden.
func (s *Service) authzRequireOrgAdmin(ctx context.Context, client *ent.Client, actorID, orgID string) (*ent.OrgMember, error) {
	membership, err := s.authzCheckMember(ctx, client, actorID, orgID)
	if err != nil {
		return nil, err
	}

	roleRecord, err := client.Role.Query().
		Where(role.ID(membership.RoleID)).
		WithPermissions().
		Only(ctx)
	if err != nil {
		return nil, ErrForbidden
	}

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

// Slugify derives a URL-safe slug from an arbitrary string, lowercasing it and
// collapsing every run of unsupported characters into a single hyphen.
func Slugify(input string) string {
	cleaned := strings.ToLower(strings.TrimSpace(input))
	slug := nonAlphanumericRegex.ReplaceAllString(cleaned, "-")
	return strings.Trim(slug, "-")
}

// ensureDefaultRole resolves roleSlug within the tenant, creating the role if it
// does not exist yet.
//
// The argument is accepted as either a slug or a role ID, because callers pass
// whichever the API client supplied. Returns the resolved or created role.
func (s *Service) ensureDefaultRole(ctx context.Context, client *ent.Client, tenantID, roleSlug, roleName string) (*ent.Role, error) {
	r, err := client.Role.Query().
		Where(role.TenantID(tenantID), role.Slug(roleSlug)).
		Only(ctx)
	if err == nil {
		return r, nil
	}

	r, err = client.Role.Query().
		Where(role.TenantID(tenantID), role.ID(roleSlug)).
		Only(ctx)
	if err == nil {
		return r, nil
	}

	roleID := fmt.Sprintf("role_%s", uuid.New().String()[:12])
	return client.Role.Create().
		SetID(roleID).
		SetTenantID(tenantID).
		SetName(roleName).
		SetSlug(roleSlug).
		SetDescription(fmt.Sprintf("Default %s role", roleName)).
		Save(ctx)
}

// CreateOrganization creates an organization and makes the creator its first
// org_admin.
//
// The slug is derived from the name when the caller supplies none, and must be
// unique within the tenant. Returns ErrOrgSlugExists on collision,
// ErrMetadataTooLarge for oversized metadata, or a validation sentinel from
// req.Validate.
func (s *Service) CreateOrganization(ctx context.Context, tenantID, actorID string, req CreateOrgRequest, ip, userAgent string) (*OrgResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := s.validateMetadataSize(req.Metadata); err != nil {
		return nil, err
	}

	if req.Slug == "" {
		req.Slug = Slugify(req.Name)
	}

	client := s.factory.GetClient(ctx, tenantID, "")

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

	orgAdminRole, err := s.ensureDefaultRole(ctx, client, tenantID, "org_admin", "Organization Admin")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve org_admin role: %w", err)
	}

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

	// The creator's membership is what later grants them admin rights over the
	// organization they just made. A tenant-admin caller passes no actor, so
	// there is nobody to enroll.
	if actorID != "" {
		_, err = client.OrgMember.Create().
			SetID(memID).
			SetOrganizationID(orgID).
			SetUserID(actorID).
			SetRoleID(orgAdminRole.ID).
			SetAssignedByUserID(actorID).
			Save(ctx)
		if err != nil {
			fmt.Printf("[Org Service] Warning: failed to auto-assign creator membership: %v\n", err)
		}
	}

	s.logAudit(ctx, tenantID, actorID, "org.created", "organization", orgID, map[string]interface{}{
		"name": req.Name,
		"slug": req.Slug,
	}, ip, userAgent)

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

// GetOrganization returns an organization within the tenant.
//
// The caller must be a member; isAdmin marks the tenant-admin tier, which
// legitimately operates across every organization and so bypasses that check.
// Returns ErrOrgNotFound or ErrNotAMember.
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

	if !isAdmin {
		_, err := s.authzCheckMember(ctx, client, actorID, orgID)
		if err != nil {
			return nil, err
		}
	}

	return s.toOrgResponse(o), nil
}

// ListOrganizationsForUser returns the organizations userID belongs to within the
// tenant. The membership itself is the authorization, so no further check applies.
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
		// Memberships are queried by user, not by tenant, so the organization's
		// own tenant is re-checked before it is returned.
		if m.Edges.Organization != nil && m.Edges.Organization.TenantID == tenantID {
			responses = append(responses, s.toOrgResponse(m.Edges.Organization))
		}
	}

	return responses, nil
}

// ListOrganizationsForTenant returns every organization under the tenant. It
// backs the tenant-admin listing and performs no per-organization check.
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

// UpdateOrganization applies a partial update to an organization.
//
// The caller must hold org_admin; isAdmin marks the tenant-admin tier, which
// bypasses that check. A changed slug must stay unique within the tenant.
// Returns ErrOrgNotFound, ErrOrgSlugExists, ErrMetadataTooLarge, or an
// authorization sentinel.
func (s *Service) UpdateOrganization(ctx context.Context, tenantID, actorID, orgID string, req UpdateOrgRequest, isAdmin bool, ip, userAgent string) (*OrgResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := s.validateMetadataSize(req.Metadata); err != nil {
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

// DeleteOrganization removes an organization together with its memberships and
// invitations.
//
// The caller must hold org_admin; isAdmin marks the tenant-admin tier, which
// bypasses that check. Returns ErrOrgNotFound or an authorization sentinel.
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

	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return err
		}
	}

	// Dependent rows go first so foreign keys never block the delete, and so no
	// membership or pending invitation outlives the organization it points at.
	_, _ = client.OrgMember.Delete().Where(orgmember.OrganizationID(orgID)).Exec(ctx)
	_, _ = client.OrgInvitation.Delete().Where(orginvitation.OrganizationID(orgID)).Exec(ctx)
	if err := client.Organization.DeleteOne(o).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}

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

// ListOrgMembers returns an organization's members.
//
// The caller must be a member; isAdmin marks the tenant-admin tier, which
// bypasses that check. Returns ErrOrgNotFound or ErrNotAMember.
func (s *Service) ListOrgMembers(ctx context.Context, tenantID, orgID string, actorID string, isAdmin bool, limit, offset int) ([]*OrgMemberResponse, error) {
	if limit <= 0 {
		limit = DefaultPaginationLimit
	}
	if limit > MaxPaginationLimit {
		limit = MaxPaginationLimit
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	exists, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Exist(ctx)
	if err != nil || !exists {
		return nil, ErrOrgNotFound
	}

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

// AddMember places a user in an organization with a given role, bypassing the
// invitation flow.
//
// The caller must hold org_admin; isAdmin marks the tenant-admin tier, which
// bypasses that check. Returns ErrOrgNotFound, ErrMemberAlreadyExists, or an
// authorization sentinel.
func (s *Service) AddMember(ctx context.Context, tenantID, actorID, orgID string, req AddMemberRequest, isAdmin bool, ip, userAgent string) (*OrgMemberResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	exists, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Exist(ctx)
	if err != nil || !exists {
		return nil, ErrOrgNotFound
	}

	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return nil, err
		}
	}

	alreadyMember, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(orgID), orgmember.UserID(req.UserID)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing membership: %w", err)
	}
	if alreadyMember {
		return nil, ErrMemberAlreadyExists
	}

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

// UpdateMemberRole changes a member's role within an organization.
//
// The caller must hold org_admin; isAdmin marks the tenant-admin tier, which
// bypasses that check. Returns ErrMemberNotFound or an authorization sentinel.
func (s *Service) UpdateMemberRole(ctx context.Context, tenantID, actorID, orgID, userID string, req UpdateMemberRoleRequest, isAdmin bool, ip, userAgent string) (*OrgMemberResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

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
//
// The caller must hold org_admin; isAdmin marks the tenant-admin tier, which
// bypasses that check. Returns ErrMemberNotFound or an authorization sentinel.
func (s *Service) RemoveMember(ctx context.Context, tenantID, actorID, orgID, userID string, isAdmin bool, ip, userAgent string) error {
	client := s.factory.GetClient(ctx, tenantID, "")

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

// toOrgResponse converts an organization entity to its API representation,
// returning nil for a nil entity.
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

// toOrgMemberResponse converts a membership entity to its API representation,
// returning nil for a nil entity.
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

// logAudit records an organization event on the tenant's audit trail.
//
// Failures are swallowed: an unwritable audit row must not fail the operation
// that has already succeeded. An actor prefixed "key_", or the literal "system",
// is recorded as the admin tier rather than as an end user.
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
