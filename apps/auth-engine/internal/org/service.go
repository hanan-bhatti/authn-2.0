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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
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
	//
	// environment is the environment the event originated in, and decides which
	// of the tenant's endpoints receive it.
	Dispatch(tenantID, environment, eventType string, data map[string]interface{})
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

// OrgAdminRoleSlug is the role slug that carries organization-admin rights. It is
// the slug CreateOrganization grants the creator.
const OrgAdminRoleSlug = "org_admin"

// roleGrantsOrgAdmin reports whether a role carries organization-admin rights.
//
// Rights come from the org_admin slug or from a role holding a namespace-wide
// grant over the organization surface. A whole-namespace grant is deliberately
// required rather than a single matching permission: a role granted only
// "orgs:write" is meant to edit organization fields, and treating that as admin
// would also hand it member removal and organization deletion.
//
// The role must have been loaded with its permissions edge; one loaded without it
// is read as slug-only, which is why callers that decide authorization load the
// edge. A nil role grants nothing, so a membership whose role cannot be resolved
// is not an admin.
//
// Every caller that asks "is this member an admin" goes through here — the
// authorization checks, the is_admin field on OrgResponse, and the last-admin
// guard. A guard using a narrower rule than the check would refuse a removal that
// leaves a capable administrator behind.
func roleGrantsOrgAdmin(r *ent.Role) bool {
	if r == nil {
		return false
	}
	if r.Slug == OrgAdminRoleSlug {
		return true
	}
	for _, perm := range r.Edges.Permissions {
		if perm.Action == "*" || perm.Action == "orgs:*" || perm.Action == "members:*" {
			return true
		}
	}
	return false
}

// authzRequireOrgAdmin verifies that actorID holds organization-admin rights over
// orgID and returns the membership.
//
// This is the required check for every mutating operation: update, delete,
// member changes and invitations. Returns ErrNotAMember or ErrForbidden.
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

	if !roleGrantsOrgAdmin(roleRecord) {
		return nil, ErrForbidden
	}

	return membership, nil
}

// countOrgAdmins returns how many members of orgID hold organization-admin
// rights, ignoring any whose user ID appears in excluding.
//
// Used by the guards that must not let an organization lose its last
// administrator. The exclusion list is how a caller asks the counterfactual
// question — "how many admins remain if this member goes" — without writing
// anything first.
//
// Every membership's role is loaded with its permissions in one query, because
// roleGrantsOrgAdmin reads that edge and a per-member round trip would make the
// guard cost grow with the organization.
func countOrgAdmins(ctx context.Context, client *ent.Client, orgID string, excluding ...string) (int, error) {
	skip := make(map[string]struct{}, len(excluding))
	for _, id := range excluding {
		skip[id] = struct{}{}
	}

	members, err := client.OrgMember.Query().
		Where(orgmember.OrganizationID(orgID)).
		WithRole(func(q *ent.RoleQuery) { q.WithPermissions() }).
		All(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count organization administrators: %w", err)
	}

	count := 0
	for _, m := range members {
		if _, excluded := skip[m.UserID]; excluded {
			continue
		}
		if roleGrantsOrgAdmin(m.Edges.Role) {
			count++
		}
	}

	return count, nil
}

// SoleAdminOrganization is an organization whose only administrator is one
// particular user.
type SoleAdminOrganization struct {
	// ID is the organization identifier.
	ID string `json:"id"`
	// Name is the display name, for naming the workspace to the reader.
	Name string `json:"name"`
	// Slug is the URL-safe identifier.
	Slug string `json:"slug"`
	// OtherMembers counts the members other than that user. Zero means the
	// organization would be left empty rather than leaderless, which is a
	// different problem and has a different answer.
	OtherMembers int `json:"other_members"`
}

// SoleAdminOrganizations returns every organization in which userID is the only
// member holding organization-admin rights.
//
// Exported and taking a client rather than hanging off Service, so the account
// deletion path in internal/user can ask the question without depending on this
// package's constructor or its webhook dispatcher. The rule it applies is the same
// roleGrantsOrgAdmin the authorization checks use, which is the point of putting
// it here rather than restating it there.
//
// Environments are not filtered. A caller deleting an account is asking about
// every obligation that account holds, and a live workspace left leaderless by a
// deletion performed in test is still leaderless.
func SoleAdminOrganizations(ctx context.Context, client *ent.Client, userID string) ([]SoleAdminOrganization, error) {
	memberships, err := client.OrgMember.Query().
		Where(orgmember.UserID(userID)).
		WithOrganization().
		WithRole(func(q *ent.RoleQuery) { q.WithPermissions() }).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query organization memberships: %w", err)
	}

	sole := make([]SoleAdminOrganization, 0)
	for _, m := range memberships {
		if m.Edges.Organization == nil || !roleGrantsOrgAdmin(m.Edges.Role) {
			continue
		}

		remaining, err := countOrgAdmins(ctx, client, m.OrganizationID, userID)
		if err != nil {
			return nil, err
		}
		if remaining > 0 {
			continue
		}

		total, err := client.OrgMember.Query().
			Where(orgmember.OrganizationID(m.OrganizationID)).
			Count(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to count organization members: %w", err)
		}

		sole = append(sole, SoleAdminOrganization{
			ID:           m.Edges.Organization.ID,
			Name:         m.Edges.Organization.Name,
			Slug:         m.Edges.Organization.Slug,
			OtherMembers: total - 1,
		})
	}

	return sole, nil
}

// deleteOrgDependents removes every row that points at orgID, leaving nothing
// holding a foreign key to the organization.
//
// Three tables reference an organization and all three keys are declared with no
// delete action, so this is not cleanup after the fact — it is what makes the
// organization deletable at all. A table added to that set and missed here turns
// every deletion of an affected organization into a foreign-key failure, which is
// why the errors are returned rather than ignored: the message then names the
// table instead of surfacing as an unexplained failure one statement later.
//
// client may be a transaction-bound client from Tx.Client(), which is how the
// account-deletion path in internal/user reuses this without restating the order.
func deleteOrgDependents(ctx context.Context, client *ent.Client, orgID string) error {
	if _, err := client.OrgMember.Delete().Where(orgmember.OrganizationID(orgID)).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete organization memberships: %w", err)
	}
	if _, err := client.OrgInvitation.Delete().Where(orginvitation.OrganizationID(orgID)).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete organization invitations: %w", err)
	}
	if _, err := client.SAMLConnection.Delete().Where(samlconnection.OrganizationID(orgID)).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete organization SSO connections: %w", err)
	}
	return nil
}

// DeleteOrganizationWithDependents removes an organization and everything that
// references it, with no authorization check of its own.
//
// Exported for the account-deletion path in internal/user, which reaches here
// having already established that the account being erased is the organization's
// only member — so there is no membership left to authorize against and nobody to
// strand. Every other caller goes through DeleteOrganization, which checks
// org_admin first.
//
// client is expected to be transaction-bound, so a failure part-way leaves the
// organization intact rather than half-dismantled.
func DeleteOrganizationWithDependents(ctx context.Context, client *ent.Client, orgID string) error {
	if err := deleteOrgDependents(ctx, client, orgID); err != nil {
		return err
	}
	if err := client.Organization.DeleteOneID(orgID).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete organization: %w", err)
	}
	return nil
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

// orgEnvironment is the environment an organization's events belong to.
//
// Read from the organization rather than from the caller's credential, because an
// event belongs where its subject lives: a tenant administrator holding a live key
// who edits a sandbox organization has produced a sandbox event, and reporting it
// as live would deliver it to the tenant's production subscribers.
//
// An unreadable organization yields "", which the webhook dispatcher drops. That
// is deliberate — an event whose origin cannot be established is worth losing,
// and by the time this is called the operation it describes has already
// succeeded, so the caller is not failed over a notification.
func (s *Service) orgEnvironment(ctx context.Context, client *ent.Client, tenantID, orgID string) string {
	o, err := client.Organization.Query().
		Where(organization.TenantID(tenantID), organization.ID(orgID)).
		Only(ctx)
	if err != nil {
		return ""
	}
	return string(o.Environment)
}

// toOrgResponse converts an organization entity to its API representation,
// returning nil for a nil entity.
//
// callerIsAdmin is passed rather than derived because this mapper has no view of
// who is asking, and the answer differs per caller for the same row. It is a
// parameter instead of a defaulted field so that a call site added later has to
// answer the question: a field defaulting to false would quietly tell an
// administrator they are not one, and a client hiding its controls on that
// answer would be wrong in the direction that looks like a bug in the client.
func (s *Service) toOrgResponse(o *ent.Organization, callerIsAdmin bool) *OrgResponse {
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
		IsAdmin:     callerIsAdmin,
		CreatedAt:   o.CreatedAt,
	}
}

// toOrgMemberResponse converts a membership entity to its API representation,
// returning nil for a nil entity.
//
// r is the membership's role, or nil when it was not loaded. The role's name and
// slug travel with the membership because a role ID answers nothing on its own
// and the roles endpoint that would resolve it is registered on the secret-key
// group — so a browser session holding only a role ID cannot tell an
// administrator from a member. IsAdmin comes from the same predicate the
// authorization checks use, which is what makes it safe for a client to hide a
// control on.
func (s *Service) toOrgMemberResponse(m *ent.OrgMember, r *ent.Role) *OrgMemberResponse {
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
	if r != nil {
		resp.RoleSlug = r.Slug
		resp.RoleName = r.Name
		resp.IsAdmin = roleGrantsOrgAdmin(r)
	}
	if m.AssignedByUserID != nil {
		resp.AssignedByUserID = *m.AssignedByUserID
	}
	return resp
}

// loadRole fetches a role with its permissions, returning nil when it cannot be
// read.
//
// Nil rather than an error: the role decorates a response whose subject —  the
// membership — has already been written or read successfully, and failing the
// whole operation over a display field would turn a cosmetic gap into an outage.
// A nil role leaves role_slug and role_name absent and is_admin false, which is
// the safe reading for a client deciding whether to show an admin control.
func (s *Service) loadRole(ctx context.Context, client *ent.Client, roleID string) *ent.Role {
	r, err := client.Role.Query().
		Where(role.ID(roleID)).
		WithPermissions().
		Only(ctx)
	if err != nil {
		return nil
	}
	return r
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
