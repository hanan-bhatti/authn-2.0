/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/types.go
 * Tier: Domain Model Layer / Request & Response DTOs
 *
 * Description: Data transfer objects and error definitions for User Self-Service
 *              Profile, Password, Recovery Email, Phone, and Account settings.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"errors"
	"time"
)

var (
	ErrUserNotFound             = errors.New("user account not found")
	ErrIncorrectPassword        = errors.New("incorrect current password")
	ErrEmailAlreadyInUse        = errors.New("email address is already in use by another account")
	ErrInvalidVerificationToken = errors.New("invalid or expired verification token")
	ErrNoRecoveryEmail          = errors.New("no secondary recovery email configured")
	ErrCannotUnlinkLastAuth     = errors.New("cannot unlink social account: user has no password set and this is the only login method")
	ErrSocialNotConnected       = errors.New("social provider is not connected to this account")
)

type UserProfileResponse struct {
	ID                    string                 `json:"id"`
	TenantID              string                 `json:"tenant_id"`
	Email                 string                 `json:"email"`
	EmailVerified         bool                   `json:"email_verified"`
	Name                  string                 `json:"name,omitempty"`
	PhoneNumber           string                 `json:"phone_number,omitempty"`
	PhoneVerified         bool                   `json:"phone_verified"`
	RecoveryEmail         string                 `json:"recovery_email,omitempty"`
	RecoveryEmailVerified bool                   `json:"recovery_email_verified"`
	AvatarURL             string                 `json:"avatar_url,omitempty"`
	Locale                string                 `json:"locale,omitempty"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

type UpdateProfileRequest struct {
	Name      *string                `json:"name,omitempty"`
	AvatarURL *string                `json:"avatar_url,omitempty"`
	Locale    *string                `json:"locale,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type RequestEmailChangeRequest struct {
	NewEmail string `json:"new_email"`
}

type SetRecoveryEmailRequest struct {
	RecoveryEmail string `json:"recovery_email"`
}

type SetPhoneNumberRequest struct {
	PhoneNumber string `json:"phone_number"`
}

type VerifyPhoneOTPRequest struct {
	Code string `json:"code"`
}

type DeleteAccountRequest struct {
	Password string `json:"password"`
}

type LinkedSocialAccount struct {
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email,omitempty"`
	ConnectedAt    time.Time `json:"connected_at"`
}
