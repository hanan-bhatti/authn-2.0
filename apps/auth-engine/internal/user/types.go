/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/types.go
 * Tier: Domain Model Layer / Request & Response DTOs
 *
 * Description: Request and response payloads and sentinel errors for the user
 *              self-service surface: profile, password, primary and recovery email,
 *              phone, linked social accounts and account erasure.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"errors"
	"time"
)

// Sentinel errors for the user self-service surface. Handlers match on these with
// errors.Is to choose a status code, so their identity is what matters, not their
// text.
var (
	// ErrUserNotFound reports that no account matches the requested identifier.
	ErrUserNotFound = errors.New("user account not found")
	// ErrIncorrectPassword reports a failed re-authentication on an operation
	// that requires the caller to confirm their current password.
	ErrIncorrectPassword = errors.New("incorrect current password")
	// ErrEmailAlreadyInUse reports that another account in the same tenant and
	// environment already holds the requested address.
	ErrEmailAlreadyInUse = errors.New("email address is already in use by another account")
	// ErrInvalidVerificationToken reports a verification token that is unknown,
	// already consumed, or past its expiry. The three cases are deliberately
	// indistinguishable to the caller.
	ErrInvalidVerificationToken = errors.New("invalid or expired verification token")
	// ErrNoRecoveryEmail reports that no secondary recovery address is configured.
	ErrNoRecoveryEmail = errors.New("no secondary recovery email configured")
	// ErrCannotUnlinkLastAuth reports a refusal to remove the only means of
	// signing in, which would lock the user out of their own account.
	ErrCannotUnlinkLastAuth = errors.New("cannot unlink social account: user has no password set and this is the only login method")
	// ErrSocialNotConnected reports that the named provider is not linked.
	ErrSocialNotConnected = errors.New("social provider is not connected to this account")
)

// UserProfileResponse is the account profile returned to its owner.
type UserProfileResponse struct {
	// ID is the user identifier.
	ID string `json:"id"`
	// TenantID is the tenant the account belongs to.
	TenantID string `json:"tenant_id"`
	// Email is the primary address, used to sign in.
	Email string `json:"email"`
	// EmailVerified reports whether the primary address has been confirmed.
	EmailVerified bool `json:"email_verified"`
	// Name is the display name.
	Name string `json:"name,omitempty"`
	// PhoneNumber is the registered phone number.
	PhoneNumber string `json:"phone_number,omitempty"`
	// PhoneVerified reports whether the phone number has been confirmed.
	PhoneVerified bool `json:"phone_verified"`
	// RecoveryEmail is the secondary address used for account recovery.
	RecoveryEmail string `json:"recovery_email,omitempty"`
	// RecoveryEmailVerified reports whether the recovery address has been
	// confirmed. An unverified address must not be trusted for recovery.
	RecoveryEmailVerified bool `json:"recovery_email_verified"`
	// AvatarURL is the profile image URL.
	AvatarURL string `json:"avatar_url,omitempty"`
	// Locale is the user's preferred language tag.
	Locale string `json:"locale,omitempty"`
	// Metadata is the caller-defined attribute bag stored on the account.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// CreatedAt is when the account was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the account was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateProfileRequest carries a partial profile update. A nil field is left
// unchanged, which is why each is a pointer.
type UpdateProfileRequest struct {
	// Name replaces the display name.
	Name *string `json:"name,omitempty"`
	// AvatarURL replaces the profile image URL.
	AvatarURL *string `json:"avatar_url,omitempty"`
	// Locale replaces the preferred language tag.
	Locale *string `json:"locale,omitempty"`
	// Metadata is merged key by key into the existing metadata rather than
	// replacing it, so a partial update cannot drop unrelated keys.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ChangePasswordRequest carries a self-service password change.
type ChangePasswordRequest struct {
	// CurrentPassword re-authenticates the caller. It is required for any account
	// that has a password set.
	CurrentPassword string `json:"current_password"`
	// NewPassword is the replacement, checked against the tenant password policy.
	NewPassword string `json:"new_password"`
}

// RequestEmailChangeRequest starts a change of the primary email address.
type RequestEmailChangeRequest struct {
	// NewEmail is the proposed address. It only takes effect once the
	// verification link sent to it is followed.
	NewEmail string `json:"new_email"`
}

// SetRecoveryEmailRequest registers a secondary recovery address.
type SetRecoveryEmailRequest struct {
	// RecoveryEmail is the proposed address, stored unverified until confirmed.
	RecoveryEmail string `json:"recovery_email"`
}

// SetPhoneNumberRequest registers a phone number for the account.
type SetPhoneNumberRequest struct {
	// PhoneNumber is the proposed number in E.164 form.
	PhoneNumber string `json:"phone_number"`
}

// VerifyPhoneOTPRequest confirms a phone number with a one-time code.
type VerifyPhoneOTPRequest struct {
	// Code is the one-time code delivered by SMS.
	Code string `json:"code"`
}

// DeleteAccountRequest confirms self-service account erasure.
type DeleteAccountRequest struct {
	// Password re-authenticates the caller before the account is destroyed.
	Password string `json:"password"`
}

// LinkedSocialAccount is one OAuth identity connected to the account.
type LinkedSocialAccount struct {
	// Provider is the social provider name, such as "google" or "github".
	Provider string `json:"provider"`
	// ProviderUserID is the account's stable identifier at that provider.
	ProviderUserID string `json:"provider_user_id"`
	// Email is the address the provider reported, if any.
	Email string `json:"email,omitempty"`
	// ConnectedAt is when the identity was linked.
	ConnectedAt time.Time `json:"connected_at"`
}
