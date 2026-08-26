/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/types.go
 * Tier: Business Logic Layer / DTOs & Validation
 *
 * Description: Request and response payloads, sentinel errors and the validation bounds
 *              they enforce for B2B organizations and team member invitations (FR-15).
 *              Each request type validates and normalises itself, so the service layer
 *              works from trimmed, lowercased, in-range values.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package org

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Validation bounds for organization fields and listings.
const (
	// MinOrgNameLength is the shortest accepted organization name.
	MinOrgNameLength = 2
	// MaxOrgNameLength is the longest accepted organization name.
	MaxOrgNameLength = 100
	// MinOrgSlugLength is the shortest accepted slug.
	MinOrgSlugLength = 2
	// MaxOrgSlugLength is the longest accepted slug.
	MaxOrgSlugLength = 50
	// MaxLogoURLLength is the longest accepted logo URL.
	MaxLogoURLLength = 2048
	// MaxMetadataSizeBytes caps an organization's serialized JSON metadata,
	// bounding how much caller-controlled data one row can hold.
	MaxMetadataSizeBytes = 10240
	// DefaultPaginationLimit is the page size used when the caller names none.
	DefaultPaginationLimit = 20
	// MaxPaginationLimit is the largest page a caller may request. Larger values
	// are clamped rather than rejected.
	MaxPaginationLimit = 100
	// MinInvitationExpiryHrs is the shortest custom invitation lifetime, 1 hour.
	MinInvitationExpiryHrs = 1
	// MaxInvitationExpiryHrs is the longest custom invitation lifetime, 30 days.
	MaxInvitationExpiryHrs = 720
	// DefaultInviteExpiryHrs is the invitation lifetime when the caller names
	// none, 7 days. It mirrors the InvitationTTL setting, which this package
	// cannot yet read because its constructor takes no *config.Config.
	DefaultInviteExpiryHrs = 168
)

var (
	// SlugRegex permits lowercase alphanumeric segments joined by single hyphens.
	SlugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Sentinel errors for the organization surface. Handlers match on these with
// errors.Is to choose a status code, so their identity is what matters, not their
// text. Matching on identity rather than message substrings also keeps a wrapped
// database error from being mistaken for one of them.
var (
	// ErrOrgNotFound reports that no organization matches within the tenant.
	ErrOrgNotFound = errors.New("organization not found")
	// ErrUserNotFound reports that no account in the tenant matches the caller.
	// Reachable only from the invitation inbox, which reads the caller's own
	// verified address before it can match anything to it.
	ErrUserNotFound = errors.New("user account not found")
	// ErrOrgSlugExists reports a slug collision inside the tenant's environment. The
	// message names the environment because the slug is still claimable in the other
	// one, and a caller told only "in this tenant" would stop looking.
	ErrOrgSlugExists = errors.New("organization slug already exists in this environment")
	// ErrInvalidOrgName reports a name outside the permitted length range.
	ErrInvalidOrgName = fmt.Errorf("organization name must be between %d and %d characters", MinOrgNameLength, MaxOrgNameLength)
	// ErrInvalidOrgSlug reports a slug of the wrong length or shape.
	ErrInvalidOrgSlug = fmt.Errorf("organization slug must be %d-%d lowercase alphanumeric characters or hyphens", MinOrgSlugLength, MaxOrgSlugLength)
	// ErrInvalidLogoURL reports a malformed or over-long logo URL.
	ErrInvalidLogoURL = errors.New("invalid logo URL format")
	// ErrMetadataTooLarge reports metadata whose serialized JSON exceeds the cap.
	ErrMetadataTooLarge = fmt.Errorf("metadata exceeds maximum allowed size of %d bytes", MaxMetadataSizeBytes)
	// ErrMemberAlreadyExists reports that the user already belongs to the org.
	ErrMemberAlreadyExists = errors.New("user is already a member of this organization")
	// ErrMemberNotFound reports that no membership links the user and the org.
	ErrMemberNotFound = errors.New("organization membership not found")
	// ErrInvalidRole reports a missing or unresolvable role ID or slug.
	ErrInvalidRole = errors.New("invalid role ID or slug specified")
	// ErrInvitationNotFound reports that no invitation matches.
	ErrInvitationNotFound = errors.New("invitation not found")
	// ErrInvitationExpired reports an invitation past its expiry.
	ErrInvitationExpired = errors.New("invitation has expired")
	// ErrInvitationAccepted reports an invitation already redeemed. Invitations
	// are single-use.
	ErrInvitationAccepted = errors.New("invitation has already been accepted")
	// ErrInvitationEnvironmentMismatch reports a redeemer signed in against one
	// environment redeeming an invitation belonging to the other.
	ErrInvitationEnvironmentMismatch = errors.New("this invitation belongs to a different environment than the signed-in account")
	// ErrInvalidEmail reports a malformed email address.
	ErrInvalidEmail = errors.New("invalid email address format")
	// ErrDomainNotAllowed reports an address barred by tenant organization policy.
	ErrDomainNotAllowed = errors.New("email domain is not permitted by tenant organization policy")
	// ErrMaxMembersExceeded reports that the organization is at its member cap.
	ErrMaxMembersExceeded = errors.New("organization has reached the maximum allowed member count")
	// ErrMaxOrgsExceeded reports that the tenant is at its organization cap.
	ErrMaxOrgsExceeded = errors.New("tenant has reached the maximum allowed organizations limit")
	// ErrInvalidInvitationToken reports a missing invitation token.
	ErrInvalidInvitationToken = errors.New("invitation_token is required")
	// ErrForbidden reports a member who lacks the role the operation requires.
	ErrForbidden = errors.New("forbidden: insufficient permissions for this operation")
	// ErrNotAMember reports a caller with no membership in the organization.
	ErrNotAMember = errors.New("forbidden: user is not a member of this organization")
	// ErrLastOrgAdmin reports an operation that would leave the organization with
	// no administrator. An organization in that state cannot be renamed, cannot
	// invite anyone and cannot be deleted by its own members, so it is
	// unrecoverable without tenant-level intervention.
	ErrLastOrgAdmin = errors.New("this would leave the organization without an administrator: grant another member organization-admin rights first, or delete the organization instead")
)

// CreateOrgRequest is the payload to create an organization.
type CreateOrgRequest struct {
	// Name is the display name.
	Name string `json:"name"`
	// Slug is the URL-safe identifier. When empty it is derived from Name.
	Slug string `json:"slug,omitempty"`
	// LogoURL is an optional logo image URL.
	LogoURL string `json:"logo_url,omitempty"`
	// Metadata is an optional caller-defined attribute bag, capped at
	// MaxMetadataSizeBytes once serialized.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate normalises the request in place and reports the first bound it
// violates: ErrInvalidOrgName, ErrInvalidOrgSlug or ErrInvalidLogoURL.
//
// Metadata size is not checked here, because it is bounded by a configurable
// limit the service layer owns.
func (r *CreateOrgRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if len(r.Name) < MinOrgNameLength || len(r.Name) > MaxOrgNameLength {
		return ErrInvalidOrgName
	}

	r.Slug = strings.TrimSpace(strings.ToLower(r.Slug))
	if r.Slug != "" {
		if len(r.Slug) < MinOrgSlugLength || len(r.Slug) > MaxOrgSlugLength || !SlugRegex.MatchString(r.Slug) {
			return ErrInvalidOrgSlug
		}
	}

	r.LogoURL = strings.TrimSpace(r.LogoURL)
	if r.LogoURL != "" {
		if len(r.LogoURL) > MaxLogoURLLength {
			return ErrInvalidLogoURL
		}
		if _, err := url.ParseRequestURI(r.LogoURL); err != nil {
			return ErrInvalidLogoURL
		}
	}

	return nil
}

// UpdateOrgRequest is the payload to change organization settings. A nil field is
// left unchanged, which is why each is a pointer.
type UpdateOrgRequest struct {
	// Name replaces the display name.
	Name *string `json:"name,omitempty"`
	// Slug replaces the URL-safe identifier, subject to tenant uniqueness.
	Slug *string `json:"slug,omitempty"`
	// LogoURL replaces the logo image URL.
	LogoURL *string `json:"logo_url,omitempty"`
	// Metadata replaces the attribute bag wholesale, capped at
	// MaxMetadataSizeBytes once serialized.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate normalises the supplied fields in place and reports the first bound
// they violate: ErrInvalidOrgName, ErrInvalidOrgSlug or ErrInvalidLogoURL.
//
// Metadata size is not checked here, because it is bounded by a configurable
// limit the service layer owns.
func (r *UpdateOrgRequest) Validate() error {
	if r.Name != nil {
		name := strings.TrimSpace(*r.Name)
		if len(name) < MinOrgNameLength || len(name) > MaxOrgNameLength {
			return ErrInvalidOrgName
		}
		*r.Name = name
	}

	if r.Slug != nil {
		slug := strings.TrimSpace(strings.ToLower(*r.Slug))
		if len(slug) < MinOrgSlugLength || len(slug) > MaxOrgSlugLength || !SlugRegex.MatchString(slug) {
			return ErrInvalidOrgSlug
		}
		*r.Slug = slug
	}

	if r.LogoURL != nil && *r.LogoURL != "" {
		logo := strings.TrimSpace(*r.LogoURL)
		if len(logo) > MaxLogoURLLength {
			return ErrInvalidLogoURL
		}
		if _, err := url.ParseRequestURI(logo); err != nil {
			return ErrInvalidLogoURL
		}
		*r.LogoURL = logo
	}

	return nil
}

// AddMemberRequest is the payload to place a user in an organization directly,
// without an invitation.
type AddMemberRequest struct {
	// UserID identifies the user to add.
	UserID string `json:"user_id"`
	// RoleID is the role to grant, given as a role ID or slug.
	RoleID string `json:"role_id"`
}

// Validate normalises the request in place and reports a missing user_id or
// ErrInvalidRole for a missing role.
func (r *AddMemberRequest) Validate() error {
	r.UserID = strings.TrimSpace(r.UserID)
	r.RoleID = strings.TrimSpace(r.RoleID)
	if r.UserID == "" {
		return errors.New("user_id is required")
	}
	if r.RoleID == "" {
		return ErrInvalidRole
	}
	return nil
}

// UpdateMemberRoleRequest is the payload to change a member's role.
type UpdateMemberRoleRequest struct {
	// RoleID is the replacement role, given as a role ID or slug.
	RoleID string `json:"role_id"`
}

// Validate normalises the request in place and returns ErrInvalidRole when no
// role was given.
func (r *UpdateMemberRoleRequest) Validate() error {
	r.RoleID = strings.TrimSpace(r.RoleID)
	if r.RoleID == "" {
		return ErrInvalidRole
	}
	return nil
}

// CreateInvitationRequest is the payload to invite someone to an organization.
type CreateInvitationRequest struct {
	// Email is the address to invite.
	Email string `json:"email"`
	// RoleID is the role the invitee receives on acceptance.
	RoleID string `json:"role_id"`
	// ExpiresHrs is an optional custom lifetime in hours. Zero means
	// DefaultInviteExpiryHrs.
	ExpiresHrs int `json:"expires_hrs,omitempty"`
}

// Validate normalises the request in place, applying the default expiry when
// none was given.
//
// Returns ErrInvalidEmail, ErrInvalidRole, or an error naming the permitted
// expiry range. An out-of-range expiry is rejected rather than clamped, so a
// caller asking for a year-long invitation is told no instead of being silently
// given a week.
func (r *CreateInvitationRequest) Validate() error {
	r.Email = strings.TrimSpace(strings.ToLower(r.Email))
	if r.Email == "" {
		return ErrInvalidEmail
	}
	if _, err := mail.ParseAddress(r.Email); err != nil {
		return ErrInvalidEmail
	}

	r.RoleID = strings.TrimSpace(r.RoleID)
	if r.RoleID == "" {
		return ErrInvalidRole
	}

	if r.ExpiresHrs == 0 {
		r.ExpiresHrs = DefaultInviteExpiryHrs
	} else if r.ExpiresHrs < MinInvitationExpiryHrs || r.ExpiresHrs > MaxInvitationExpiryHrs {
		return fmt.Errorf("expires_hrs must be between %d and %d hours", MinInvitationExpiryHrs, MaxInvitationExpiryHrs)
	}

	return nil
}

// AcceptInvitationRequest is the payload to redeem an invitation token.
type AcceptInvitationRequest struct {
	// InvitationToken is the single-use token from the invitation email.
	InvitationToken string `json:"invitation_token"`
}

// Validate normalises the request in place and returns
// ErrInvalidInvitationToken when no token was given.
func (r *AcceptInvitationRequest) Validate() error {
	r.InvitationToken = strings.TrimSpace(r.InvitationToken)
	if r.InvitationToken == "" {
		return ErrInvalidInvitationToken
	}
	return nil
}

// OrgResponse is an organization as returned to callers.
type OrgResponse struct {
	// ID is the organization identifier.
	ID string `json:"id"`
	// TenantID is the tenant that owns the organization.
	TenantID string `json:"tenant_id"`
	// Environment is "test" or "live" — the environment the workspace belongs to.
	// It is echoed so a caller holding both key pairs can tell which of the two a
	// workspace came from without inspecting the key it used.
	Environment string `json:"environment"`
	// Name is the display name.
	Name string `json:"name"`
	// Slug is the URL-safe identifier, unique within the tenant and environment.
	Slug string `json:"slug"`
	// LogoURL is the logo image URL, if set.
	LogoURL string `json:"logo_url,omitempty"`
	// Metadata is the caller-defined attribute bag.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// IsAdmin reports whether the caller holds organization-admin rights here.
	//
	// The same answer the mutating endpoints will give, so a client can hide a
	// control instead of offering one that returns 403. It is per-caller, not a
	// property of the organization: two members reading the same workspace get
	// different values. A tenant-admin credential reads true everywhere, because
	// it can in fact administer every workspace in the tenant.
	IsAdmin bool `json:"is_admin"`
	// CreatedAt is when the organization was created.
	CreatedAt time.Time `json:"created_at"`
}

// OrgMemberResponse is a membership as returned to callers.
type OrgMemberResponse struct {
	// ID is the membership identifier.
	ID string `json:"id"`
	// OrganizationID is the organization the membership belongs to.
	OrganizationID string `json:"organization_id"`
	// UserID is the member.
	UserID string `json:"user_id"`
	// Name is the member's display name, absent when they have not set one.
	Name string `json:"name,omitempty"`
	// Email is the member's address. Every member of an organization may read its
	// roster, so this is visible to all of them — which is what a shared workspace
	// requires: a roster nobody can be named on cannot be administered.
	Email string `json:"email,omitempty"`
	// Username is the member's handle, absent when they have not claimed one.
	Username string `json:"username,omitempty"`
	// AvatarURL is the member's picture, absent when they have not set one.
	AvatarURL string `json:"avatar_url,omitempty"`
	// RoleID is the role held in this organization.
	RoleID string `json:"role_id"`
	// RoleSlug is the role's stable identifier, "org_admin" for an administrator.
	// Absent when the role could not be read.
	RoleSlug string `json:"role_slug,omitempty"`
	// RoleName is the role's display name, for showing beside the member. Absent
	// when the role could not be read.
	RoleName string `json:"role_name,omitempty"`
	// IsAdmin reports whether this member's role carries organization-admin
	// rights. Derived from the role's slug and permissions by the same predicate
	// the authorization checks use, so a client may rely on it.
	IsAdmin bool `json:"is_admin"`
	// AssignedByUserID is whoever granted the membership, if recorded.
	AssignedByUserID string `json:"assigned_by_user_id,omitempty"`
	// CreatedAt is when the membership was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the membership was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// OrgInvitationResponse is an invitation as returned to callers.
type OrgInvitationResponse struct {
	// ID is the invitation identifier.
	ID string `json:"id"`
	// OrganizationID is the organization being joined.
	OrganizationID string `json:"organization_id"`
	// OrganizationName is that organization's display name. Absent when the
	// organization was not loaded alongside the invitation.
	//
	// It travels with the invitation because the recipient's inbox has no other way
	// to name what they are being asked to join: they are not a member yet, so the
	// endpoint that would resolve the ID answers 403 for them.
	OrganizationName string `json:"organization_name,omitempty"`
	// Email is the invited address.
	Email string `json:"email"`
	// RoleID is the role granted on acceptance.
	RoleID string `json:"role_id"`
	// InvitedByUserID is whoever sent the invitation, if recorded.
	InvitedByUserID string `json:"invited_by_user_id,omitempty"`
	// InvitationToken is the single-use redemption secret. It is populated only
	// for the caller who created the invitation and omitted from listings, so a
	// member who can list invitations cannot redeem someone else's.
	InvitationToken string `json:"invitation_token,omitempty"`
	// Status is the lifecycle state: pending, accepted or expired.
	Status string `json:"status"`
	// ExpiresAt is when the invitation stops being redeemable.
	ExpiresAt time.Time `json:"expires_at"`
	// CreatedAt is when the invitation was created.
	CreatedAt time.Time `json:"created_at"`
}
