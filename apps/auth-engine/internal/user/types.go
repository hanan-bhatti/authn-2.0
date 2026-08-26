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
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/org"
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
	// ErrUsernameTaken reports that another account in the same tenant and
	// environment already holds the requested handle.
	ErrUsernameTaken = errors.New("username is already taken")
	// ErrUsernameInvalid reports a handle that breaks one of the naming rules. It
	// is always wrapped around the rule error from pkg/username, so a handler can
	// pass the result to username.Explain and name the rule that was broken
	// instead of reporting the value invalid and leaving the user to guess which
	// of six rules they missed.
	ErrUsernameInvalid = errors.New("username is not valid")
	// ErrTOTPRequired reports that an account with no password must supply a
	// current authenticator code to authorise a destructive operation. Its own
	// sentinel rather than a variant of ErrIncorrectPassword, because the client's
	// response differs: it has to ask for a different input, not repeat the prompt.
	ErrTOTPRequired = errors.New("enter the 6-digit code from your authenticator app to confirm: this account has no password to re-enter")
	// ErrIncorrectTOTP reports an authenticator code that did not validate.
	ErrIncorrectTOTP = errors.New("that authenticator code is not valid right now: check the current code and try again")
	// ErrReservedMetadataKey reports a metadata write naming one of the engine's
	// own keys. It is always wrapped so the message names the key that was
	// refused, since a caller told only that something was reserved has to guess
	// which of its keys to drop.
	ErrReservedMetadataKey = errors.New("metadata key is reserved")
)

// SoleOrgAdminError reports a refusal to erase an account that is the only
// administrator of organizations other people still belong to.
//
// A type rather than a sentinel because the answer is only actionable if it names
// the workspaces: "hand over an organization first" is advice, while "hand over
// Acme and Northwind first" is an instruction. Handlers match it with errors.As
// and put Organizations in the response body so the client can list them with the
// member counts that explain the refusal.
type SoleOrgAdminError struct {
	// Organizations are the workspaces blocking the deletion, each with the count
	// of members who would be left without an administrator.
	Organizations []org.SoleAdminOrganization
}

// Error names the blocking organizations, so a caller that only logs the error
// still records which ones they were.
func (e *SoleOrgAdminError) Error() string {
	names := make([]string, 0, len(e.Organizations))
	for _, o := range e.Organizations {
		names = append(names, o.Name)
	}
	return fmt.Sprintf("this account is the only administrator of %s: give another member organization-admin rights, or delete the organization, before deleting the account", strings.Join(names, ", "))
}

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
	// HasPassword reports whether the account holds a password at all. An account
	// created through a social provider or a magic link holds none.
	//
	// It is here because the step-up on a sensitive write is not the caller's
	// choice: an account with a password is checked on the password, and only one
	// without falls through to its authenticator code. Without this field a client
	// has to guess which credential to collect, and guessing wrong costs the person
	// a refused request and a second prompt for something they never set.
	HasPassword bool `json:"has_password"`
	// Username is the handle, in the form the owner typed it. Omitted when the
	// account has none: a handle is optional at signup, and an empty string here
	// would be indistinguishable from one that had been claimed and cleared.
	Username string `json:"username,omitempty"`
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
	// Username replaces the handle. An empty string releases the current one,
	// which is the only way to go back to having none — omitting the field leaves
	// it alone, since a partial update cannot distinguish "unset" from "clear".
	Username *string `json:"username,omitempty"`
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
	// Password re-authenticates the caller before the account is destroyed. It is
	// required of any account that holds one.
	Password string `json:"password"`
	// TOTPCode re-authenticates an account that holds no password — one created
	// through a social provider, a passkey or a magic link. Such an account cannot
	// be re-checked by password, and a session cookie alone is not proof enough to
	// destroy it: the session may be one someone else walked up to.
	TOTPCode string `json:"totp_code,omitempty"`
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
