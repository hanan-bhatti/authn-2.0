/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/invitation_service.go
 * Tier: Business Logic Layer / Cryptographic Invitation Engine
 *
 * Description: Cryptographic invitation logic for team member onboarding. Generates 32-byte
 *              random tokens, handles 7-day expiration logic, invitation acceptance, role assignment,
 *              audit logging, and real-time webhook event dispatching.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

// generateSecureToken creates a cryptographically random 32-byte hex token string.
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateInvitation generates a single-use cryptographically random 32-byte token and records pending invitation.
// Authorization: caller must hold org_admin (C2), OR hold admin_auth_method privilege.
func (s *Service) CreateInvitation(ctx context.Context, tenantID, actorID, orgID string, req CreateInvitationRequest, isAdmin bool, ip, userAgent string) (*OrgInvitationResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Check org existence
	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("failed to query organization: %w", err)
	}

	// Authorization check: tenant-admin tier bypasses org_admin requirement
	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return nil, err
		}
	}

	// Resolve role
	targetRole, err := s.ensureDefaultRole(ctx, client, tenantID, req.RoleID, "Invited Role")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve role: %w", err)
	}

	token, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure invitation token: %w", err)
	}

	invID := fmt.Sprintf("inv_%s", uuid.New().String()[:12])
	expiresAt := time.Now().Add(time.Duration(req.ExpiresHrs) * time.Hour)

	builder := client.OrgInvitation.Create().
		SetID(invID).
		SetOrganizationID(orgID).
		SetEmail(req.Email).
		SetRoleID(targetRole.ID).
		SetInvitationToken(token).
		SetStatus(orginvitation.StatusPending).
		SetExpiresAt(expiresAt)

	if actorID != "" {
		builder.SetInvitedByUserID(actorID)
	}

	createdInv, err := builder.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to save invitation: %w", err)
	}

	// Audit Log & Webhook
	s.logAudit(ctx, tenantID, actorID, "org.invitation_sent", "invitation", invID, map[string]interface{}{
		"org_id":     orgID,
		"email":      req.Email,
		"role_id":    targetRole.ID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.invitation_sent", map[string]interface{}{
			"invitation_id":    invID,
			"org_id":           orgID,
			"org_name":         o.Name,
			"email":            req.Email,
			"role_id":          targetRole.ID,
			"invitation_token": token,
			"expires_at":       expiresAt.Format(time.RFC3339),
		})
	}

	return s.toOrgInvitationResponse(createdInv, true), nil
}

// ListPendingInvitations returns all pending invitations for an organization.
// Authorization: caller must be an active member (C2), OR hold admin_auth_method privilege.
func (s *Service) ListPendingInvitations(ctx context.Context, tenantID, orgID string, actorID string, isAdmin bool, limit, offset int) ([]*OrgInvitationResponse, error) {
	if limit <= 0 {
		limit = DefaultPaginationLimit
	}
	if limit > MaxPaginationLimit {
		limit = MaxPaginationLimit
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	// Check org existence
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

	invitations, err := client.OrgInvitation.Query().
		Where(orginvitation.OrganizationID(orgID), orginvitation.StatusEQ(orginvitation.StatusPending)).
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query invitations: %w", err)
	}

	responses := make([]*OrgInvitationResponse, len(invitations))
	for i, inv := range invitations {
		responses[i] = s.toOrgInvitationResponse(inv, false)
	}

	return responses, nil
}

// RevokeInvitation cancels a pending invitation.
// Authorization: caller must hold org_admin (C2), OR hold admin_auth_method privilege.
func (s *Service) RevokeInvitation(ctx context.Context, tenantID, actorID, orgID, invitationID string, isAdmin bool, ip, userAgent string) error {
	client := s.factory.GetClient(ctx, tenantID, "")

	// Authorization check: tenant-admin tier bypasses org_admin requirement
	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return err
		}
	}

	inv, err := client.OrgInvitation.Query().
		Where(orginvitation.OrganizationID(orgID), orginvitation.ID(invitationID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrInvitationNotFound
		}
		return fmt.Errorf("failed to query invitation: %w", err)
	}

	if inv.Status != orginvitation.StatusPending {
		return fmt.Errorf("cannot revoke invitation with status '%s'", inv.Status)
	}

	_, err = inv.Update().SetStatus(orginvitation.StatusExpired).Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update invitation status: %w", err)
	}

	// Audit Log & Webhook
	s.logAudit(ctx, tenantID, actorID, "org.invitation_revoked", "invitation", invitationID, map[string]interface{}{
		"org_id": orgID,
		"email":  inv.Email,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.invitation_revoked", map[string]interface{}{
			"invitation_id": invitationID,
			"org_id":        orgID,
			"email":         inv.Email,
		})
	}

	return nil
}

// AcceptInvitation validates single-use token and creates organization membership for the user.
func (s *Service) AcceptInvitation(ctx context.Context, tenantID, userID string, req AcceptInvitationRequest, ip, userAgent string) (*OrgMemberResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, "")

	inv, err := client.OrgInvitation.Query().
		Where(orginvitation.InvitationToken(req.InvitationToken)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInvitationNotFound
		}
		return nil, fmt.Errorf("failed to query invitation: %w", err)
	}

	if inv.Status == orginvitation.StatusAccepted {
		return nil, ErrInvitationAccepted
	}
	if inv.Status == orginvitation.StatusExpired || time.Now().After(inv.ExpiresAt) {
		// Auto update status if expired
		if inv.Status != orginvitation.StatusExpired {
			_, _ = inv.Update().SetStatus(orginvitation.StatusExpired).Save(ctx)
		}
		return nil, ErrInvitationExpired
	}

	// Resolve or auto-provision target User in tenant database to ensure Foreign Key integrity
	var targetUser *ent.User
	if userID != "" {
		targetUser, _ = client.User.Query().
			Where(user.TenantID(tenantID), user.ID(userID)).
			Only(ctx)
	}
	if targetUser == nil {
		targetUser, _ = client.User.Query().
			Where(user.TenantID(tenantID), user.Email(inv.Email)).
			Only(ctx)
	}
	if targetUser == nil {
		newUserID := userID
		if newUserID == "" {
			newUserID = fmt.Sprintf("usr_%s", uuid.New().String()[:12])
		}
		createdUser, err := client.User.Create().
			SetID(newUserID).
			SetTenantID(tenantID).
			SetEmail(inv.Email).
			SetEmailVerified(true).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to provision user for invitation: %w", err)
		}
		targetUser = createdUser
	}
	userID = targetUser.ID

	// Check if already a member
	alreadyMember, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(inv.OrganizationID), orgmember.UserID(userID)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing membership: %w", err)
	}

	var member *ent.OrgMember
	if alreadyMember {
		// Update existing role if already a member
		m, err := client.OrgMember.Query().
			Where(orgmember.OrganizationID(inv.OrganizationID), orgmember.UserID(userID)).
			Only(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch member: %w", err)
		}
		member, err = m.Update().SetRoleID(inv.RoleID).Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to update member role: %w", err)
		}
	} else {
		// Create new OrgMember entry
		memID := fmt.Sprintf("mem_%s", uuid.New().String()[:12])
		builder := client.OrgMember.Create().
			SetID(memID).
			SetOrganizationID(inv.OrganizationID).
			SetUserID(userID).
			SetRoleID(inv.RoleID)

		if inv.InvitedByUserID != nil {
			builder.SetAssignedByUserID(*inv.InvitedByUserID)
		}

		member, err = builder.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create member: %w", err)
		}
	}

	// Update invitation status to accepted
	_, err = inv.Update().SetStatus(orginvitation.StatusAccepted).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	// Audit Log & Webhook
	s.logAudit(ctx, tenantID, userID, "org.invitation_accepted", "invitation", inv.ID, map[string]interface{}{
		"org_id":        inv.OrganizationID,
		"user_id":       userID,
		"invitation_id": inv.ID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "org.invitation_accepted", map[string]interface{}{
			"invitation_id": inv.ID,
			"org_id":        inv.OrganizationID,
			"user_id":       userID,
			"email":         inv.Email,
			"role_id":       inv.RoleID,
		})
	}

	return s.toOrgMemberResponse(member), nil
}

func (s *Service) toOrgInvitationResponse(inv *ent.OrgInvitation, includeToken bool) *OrgInvitationResponse {
	if inv == nil {
		return nil
	}
	resp := &OrgInvitationResponse{
		ID:             inv.ID,
		OrganizationID: inv.OrganizationID,
		Email:          inv.Email,
		RoleID:         inv.RoleID,
		Status:         string(inv.Status),
		ExpiresAt:      inv.ExpiresAt,
		CreatedAt:      inv.CreatedAt,
	}
	if inv.InvitedByUserID != nil {
		resp.InvitedByUserID = *inv.InvitedByUserID
	}
	if includeToken {
		resp.InvitationToken = inv.InvitationToken
	}
	return resp
}
