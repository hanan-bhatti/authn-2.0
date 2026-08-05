/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/org/types.go
 * Tier: Business Logic Layer / DTOs & Validation
 *
 * Description: Data transfer objects, request/response models, validation rules,
 *              and limit bounds for B2B Organizations & Team Member Invitations (FR-15).
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

// Validation Constants & Limit Bounds
const (
	MinOrgNameLength        = 2
	MaxOrgNameLength        = 100
	MinOrgSlugLength        = 2
	MaxOrgSlugLength        = 50
	MaxLogoURLLength        = 2048
	MaxMetadataSizeBytes    = 10240 // 10 KB
	DefaultPaginationLimit  = 20
	MaxPaginationLimit      = 100
	MinInvitationExpiryHrs  = 1   // 1 hour
	MaxInvitationExpiryHrs  = 720 // 30 days
	DefaultInviteExpiryHrs  = 168 // 7 days
)

var (
	// SlugRegex permits lowercase alphanumeric characters and single hyphens.
	SlugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Common Sentinel Errors
var (
	ErrOrgNotFound          = errors.New("organization not found")
	ErrOrgSlugExists        = errors.New("organization slug already exists in this tenant")
	ErrInvalidOrgName       = fmt.Errorf("organization name must be between %d and %d characters", MinOrgNameLength, MaxOrgNameLength)
	ErrInvalidOrgSlug       = fmt.Errorf("organization slug must be %d-%d lowercase alphanumeric characters or hyphens", MinOrgSlugLength, MaxOrgSlugLength)
	ErrInvalidLogoURL       = errors.New("invalid logo URL format")
	ErrMetadataTooLarge     = fmt.Errorf("metadata exceeds maximum allowed size of %d bytes", MaxMetadataSizeBytes)
	ErrMemberAlreadyExists  = errors.New("user is already a member of this organization")
	ErrMemberNotFound       = errors.New("organization membership not found")
	ErrInvalidRole          = errors.New("invalid role ID or slug specified")
	ErrInvitationNotFound   = errors.New("invitation not found")
	ErrInvitationExpired    = errors.New("invitation has expired")
	ErrInvitationAccepted   = errors.New("invitation has already been accepted")
	ErrInvalidEmail         = errors.New("invalid email address format")
	ErrDomainNotAllowed     = errors.New("email domain is not permitted by tenant organization policy")
	ErrMaxMembersExceeded   = errors.New("organization has reached the maximum allowed member count")
	ErrMaxOrgsExceeded      = errors.New("tenant has reached the maximum allowed organizations limit")
	ErrInvalidInvitationToken = errors.New("invitation_token is required")
)

// CreateOrgRequest represents the request payload to create a new organization.
type CreateOrgRequest struct {
	Name     string                 `json:"name"`
	Slug     string                 `json:"slug,omitempty"`     // Optional, auto-derived if empty
	LogoURL  string                 `json:"logo_url,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate checks constraints on CreateOrgRequest.
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

// UpdateOrgRequest represents the request payload to update organization settings.
type UpdateOrgRequest struct {
	Name     *string                `json:"name,omitempty"`
	Slug     *string                `json:"slug,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Validate checks constraints on UpdateOrgRequest.
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

// AddMemberRequest represents payload for adding/assigning a user to an organization directly.
type AddMemberRequest struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

// Validate checks constraints on AddMemberRequest.
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

// UpdateMemberRoleRequest represents payload to change a member's role in an organization.
type UpdateMemberRoleRequest struct {
	RoleID string `json:"role_id"`
}

// Validate checks constraints on UpdateMemberRoleRequest.
func (r *UpdateMemberRoleRequest) Validate() error {
	r.RoleID = strings.TrimSpace(r.RoleID)
	if r.RoleID == "" {
		return ErrInvalidRole
	}
	return nil
}

// CreateInvitationRequest represents request payload to send a team invitation email.
type CreateInvitationRequest struct {
	Email      string `json:"email"`
	RoleID     string `json:"role_id"`
	ExpiresHrs int    `json:"expires_hrs,omitempty"` // Optional custom expiry in hours (default 168)
}

// Validate checks constraints on CreateInvitationRequest.
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

// AcceptInvitationRequest represents payload to redeem an invitation token.
type AcceptInvitationRequest struct {
	InvitationToken string `json:"invitation_token"`
}

// Validate checks constraints on AcceptInvitationRequest.
func (r *AcceptInvitationRequest) Validate() error {
	r.InvitationToken = strings.TrimSpace(r.InvitationToken)
	if r.InvitationToken == "" {
		return ErrInvalidInvitationToken
	}
	return nil
}

// OrgResponse represents serialized Organization payload.
type OrgResponse struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	LogoURL   string                 `json:"logo_url,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// OrgMemberResponse represents serialized OrgMember payload.
type OrgMemberResponse struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	UserID           string    `json:"user_id"`
	RoleID           string    `json:"role_id"`
	AssignedByUserID string    `json:"assigned_by_user_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// OrgInvitationResponse represents serialized OrgInvitation payload.
type OrgInvitationResponse struct {
	ID              string    `json:"id"`
	OrganizationID  string    `json:"organization_id"`
	Email           string    `json:"email"`
	RoleID          string    `json:"role_id"`
	InvitedByUserID string    `json:"invited_by_user_id,omitempty"`
	InvitationToken string    `json:"invitation_token,omitempty"` // Omitted in public responses unless explicitly requested
	Status          string    `json:"status"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}
