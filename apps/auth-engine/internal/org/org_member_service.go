/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/org_member_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Organization membership management (add, update role, remove, list members).
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
)

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

	memID := idgen.New("mem")
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
