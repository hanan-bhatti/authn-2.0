/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/org_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Organization lifecycle operations (create, update, delete, get, list).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"context"
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// CreateOrganization creates an organization and makes the creator its first
// org_admin.
//
// The slug is derived from the name when the caller supplies none, and must be
// unique within the tenant and environment. Returns ErrOrgSlugExists on
// collision, ErrMetadataTooLarge for oversized metadata, or a validation
// sentinel from req.Validate.
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

	// The environment comes from the caller's scope rather than the request, so the
	// workspace is written into the one environment that can read it back. A request
	// field here would let a test key file a workspace it could not then see.
	//
	// A context naming no environment — a bypass, or provisioning — gets the schema
	// default rather than a guess, so a seeded organization lands in test and never
	// silently in live.
	environment := organization.DefaultEnvironment
	if p, ok := privacy.FromContext(ctx); ok && p.Environment != "" {
		environment = organization.Environment(p.Environment)
	}

	// Named explicitly rather than left to the interceptor, because a bypass context
	// is narrowed by nothing and would see the other environment's workspaces. This
	// check has to bound exactly what the unique index bounds, or it reports a
	// collision on a slug the insert would have accepted.
	exists, err := client.Organization.Query().
		Where(
			organization.TenantID(tenantID),
			organization.EnvironmentEQ(environment),
			organization.Slug(req.Slug),
		).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check slug uniqueness: %w", err)
	}
	if exists {
		return nil, ErrOrgSlugExists
	}

	orgID := idgen.New("org")
	memID := idgen.New("mem")

	orgAdminRole, err := s.ensureDefaultRole(ctx, client, tenantID, "org_admin", "Organization Admin")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve org_admin role: %w", err)
	}

	builder := client.Organization.Create().
		SetID(orgID).
		SetTenantID(tenantID).
		SetEnvironment(environment).
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
		s.dispatcher.Dispatch(tenantID, string(createdOrg.Environment), "org.created", map[string]interface{}{
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
// bypasses that check. A changed slug must stay unique within the tenant and the
// organization's own environment. Returns ErrOrgNotFound, ErrOrgSlugExists,
// ErrMetadataTooLarge, or an authorization sentinel.
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
		// Bounded by the environment of the row being renamed, which is what the unique
		// index bounds. A tenant renaming a test workspace is not blocked by a live one
		// already holding the name it wants.
		exists, err := client.Organization.Query().
			Where(
				organization.TenantID(tenantID),
				organization.EnvironmentEQ(o.Environment),
				organization.Slug(*req.Slug),
				organization.IDNEQ(orgID),
			).
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
		s.dispatcher.Dispatch(tenantID, string(updatedOrg.Environment), "org.updated", map[string]interface{}{
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
		s.dispatcher.Dispatch(tenantID, string(o.Environment), "org.deleted", map[string]interface{}{
			"org_id": orgID,
		})
	}

	return nil
}
