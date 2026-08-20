/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/invitation_service.go
 * Tier: Business Logic Layer / Invitation Engine
 *
 * Description: Team-member invitation lifecycle. Issues single-use invitations carrying a
 *              cryptographically random token, lists and revokes pending ones, and redeems
 *              a token into an organization membership, provisioning the invitee's user
 *              record when they do not have one yet.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

// generateSecureToken returns a 32-byte random value as a hex string.
//
// The token is the sole credential that redeems an invitation, so it comes from
// crypto/rand and is wide enough to make guessing infeasible.
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateInvitation issues a single-use invitation to join an organization and
// returns it with the redemption token attached.
//
// The caller must hold org_admin; isAdmin marks the tenant-admin tier, which
// bypasses that check. The expiry comes from req.ExpiresHrs, already defaulted
// and range-checked by req.Validate. Returns ErrOrgNotFound, a validation
// sentinel, or an authorization sentinel.
func (s *Service) CreateInvitation(ctx context.Context, tenantID, actorID, orgID string, req CreateInvitationRequest, isAdmin bool, ip, userAgent string) (*OrgInvitationResponse, error) {
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
		return nil, fmt.Errorf("failed to query organization: %w", err)
	}

	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return nil, err
		}
	}

	targetRole, err := s.ensureDefaultRole(ctx, client, tenantID, req.RoleID, "Invited Role")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve role: %w", err)
	}

	token, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure invitation token: %w", err)
	}

	invID := idgen.New("inv")
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

	s.logAudit(ctx, tenantID, actorID, "org.invitation_sent", "invitation", invID, map[string]interface{}{
		"org_id":     orgID,
		"email":      req.Email,
		"role_id":    targetRole.ID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}, ip, userAgent)

	// The webhook carries the token because delivering the invitation email is
	// the subscriber's job.
	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, string(o.Environment), "org.invitation_sent", map[string]interface{}{
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

// ListPendingInvitations returns an organization's outstanding invitations.
//
// The caller must be a member; isAdmin marks the tenant-admin tier, which
// bypasses that check. Redemption tokens are withheld from the listing, so a
// member who can see an invitation cannot redeem it. Returns ErrOrgNotFound or
// ErrNotAMember.
func (s *Service) ListPendingInvitations(ctx context.Context, tenantID, orgID string, actorID string, isAdmin bool, limit, offset int) ([]*OrgInvitationResponse, error) {
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

// RevokeInvitation cancels a pending invitation, leaving its token unredeemable.
//
// The caller must hold org_admin; isAdmin marks the tenant-admin tier, which
// bypasses that check. Only a pending invitation can be revoked. Returns
// ErrInvitationNotFound, an error naming the current status, or an authorization
// sentinel.
func (s *Service) RevokeInvitation(ctx context.Context, tenantID, actorID, orgID, invitationID string, isAdmin bool, ip, userAgent string) error {
	client := s.factory.GetClient(ctx, tenantID, "")

	if !isAdmin {
		if _, err := s.authzRequireOrgAdmin(ctx, client, actorID, orgID); err != nil {
			return err
		}
	}

	// Scoped by organization as well as ID, so an admin of one organization
	// cannot revoke another's invitation by guessing its identifier.
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

	s.logAudit(ctx, tenantID, actorID, "org.invitation_revoked", "invitation", invitationID, map[string]interface{}{
		"org_id": orgID,
		"email":  inv.Email,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, s.orgEnvironment(ctx, client, tenantID, orgID), "org.invitation_revoked", map[string]interface{}{
			"invitation_id": invitationID,
			"org_id":        orgID,
			"email":         inv.Email,
		})
	}

	return nil
}

// AcceptInvitation redeems an invitation token and returns the resulting
// membership.
//
// Possession of the token is the authorization: it is looked up on its own, since
// the redeemer is by definition not yet a member of the organization. An
// invitation that is already accepted, expired by status, or past its expiry
// timestamp is refused, and one found expired by time is marked so. When no user
// matches the caller's ID or the invited address, an account is provisioned for
// that address, because the membership needs a user row to reference. Redeeming
// as an existing member updates their role rather than duplicating the
// membership. Returns ErrInvitationNotFound, ErrInvitationAccepted or
// ErrInvitationExpired.
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
		if inv.Status != orginvitation.StatusExpired {
			_, _ = inv.Update().SetStatus(orginvitation.StatusExpired).Save(ctx)
		}
		return nil, ErrInvitationExpired
	}

	// The organization the invitation is for decides the environment: both the one
	// its events belong to and the one an account is provisioned into. The
	// invitation carries none of its own, and the redeemer arrives with a token
	// rather than a credential, so there is nothing else to read it from.
	environment := s.orgEnvironment(ctx, client, tenantID, inv.OrganizationID)
	if environment == "" {
		// The organization the invitation names is gone, so there is no environment
		// to provision into and no membership to grant. Reported as a missing
		// invitation because that is what it is from the redeemer's side.
		return nil, ErrInvitationNotFound
	}

	var targetUser *ent.User
	if userID != "" {
		targetUser, _ = client.User.Query().
			Where(user.TenantID(tenantID), user.ID(userID)).
			Only(ctx)
		// A redeemer signed in against the other environment cannot take this
		// membership: the row would point at a user the organization's own
		// environment cannot see. Provisioning them a second account under the same
		// address is not the alternative — it would split one person across two
		// environments silently — so the redemption is refused instead.
		if targetUser != nil && string(targetUser.Environment) != environment {
			return nil, ErrInvitationEnvironmentMismatch
		}
	}
	if targetUser == nil {
		// Narrowed by environment because an address is unique per environment, not
		// per tenant: a tenant holding the same address in both would match two rows
		// here, and Only reporting that ambiguity would read as no user at all.
		targetUser, _ = client.User.Query().
			Where(user.TenantID(tenantID), user.EnvironmentEQ(user.Environment(environment)), user.Email(inv.Email)).
			Only(ctx)
	}
	if targetUser == nil {
		newUserID := userID
		if newUserID == "" {
			newUserID = idgen.New("usr")
		}
		// The address is treated as verified because reaching here required the
		// token that was emailed to it.
		createdUser, err := client.User.Create().
			SetID(newUserID).
			SetTenantID(tenantID).
			SetEnvironment(user.Environment(environment)).
			SetEmail(inv.Email).
			SetEmailVerified(true).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to provision user for invitation: %w", err)
		}
		targetUser = createdUser
	}
	userID = targetUser.ID

	alreadyMember, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(inv.OrganizationID), orgmember.UserID(userID)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing membership: %w", err)
	}

	var member *ent.OrgMember
	if alreadyMember {
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
		memID := idgen.New("mem")
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

	// Marking the invitation accepted is what makes it single-use.
	_, err = inv.Update().SetStatus(orginvitation.StatusAccepted).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept invitation: %w", err)
	}

	s.logAudit(ctx, tenantID, userID, "org.invitation_accepted", "invitation", inv.ID, map[string]interface{}{
		"org_id":        inv.OrganizationID,
		"user_id":       userID,
		"invitation_id": inv.ID,
	}, ip, userAgent)

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, environment, "org.invitation_accepted", map[string]interface{}{
			"invitation_id": inv.ID,
			"org_id":        inv.OrganizationID,
			"user_id":       userID,
			"email":         inv.Email,
			"role_id":       inv.RoleID,
		})
	}

	return s.toOrgMemberResponse(member), nil
}

// toOrgInvitationResponse converts an invitation entity to its API
// representation, returning nil for a nil entity.
//
// includeToken must be true only for the caller who just created the invitation;
// every other path leaves the redemption secret out.
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
