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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"regexp"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
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

	roleID := idgen.New("role")
	return client.Role.Create().
		SetID(roleID).
		SetTenantID(tenantID).
		SetName(roleName).
		SetSlug(roleSlug).
		SetDescription(fmt.Sprintf("Default %s role", roleName)).
		Save(ctx)
}

// toOrgResponse converts an organization entity to its API representation,
// returning nil for a nil entity.
func (s *Service) toOrgResponse(o *ent.Organization) *OrgResponse {
	if o == nil {
		return nil
	}
	return &OrgResponse{
		ID:          o.ID,
		TenantID:    o.TenantID,
		Environment: string(o.Environment),
		Name:        o.Name,
		Slug:        o.Slug,
		LogoURL:     o.LogoURL,
		Metadata:    o.Metadata,
		CreatedAt:   o.CreatedAt,
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

	logID := idgen.New("log")

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
