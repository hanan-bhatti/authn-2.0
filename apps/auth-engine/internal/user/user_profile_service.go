/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/user_profile_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Profile CRUD, linked social OAuth identities, and account deletion with dependent cascades.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"context"
	"fmt"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/pushdevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/trusteddevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/useripsubnethistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userpasswordhistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/org"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/username"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

// maxNameLength is the ceiling on a display name, in bytes, matching the one
// signup applies and the width of the column behind it.
const maxNameLength = 255

// GetProfile returns the profile of userID, or ErrUserNotFound if no such
// account exists.
func (s *Service) GetProfile(ctx context.Context, userID string) (*UserProfileResponse, error) {
	u, err := s.authRepo.GetUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, ErrUserNotFound
	}

	res := &UserProfileResponse{
		ID:            u.ID,
		TenantID:      u.TenantID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		PhoneNumber:   u.PhoneNumber,
		PhoneVerified: u.PhoneVerified,
		AvatarURL:     u.AvatarURL,
		Locale:        u.Locale,
		// The caller's own attributes only. The same bag holds pending-verification
		// digests and the security-question answer hashes, and none of that is the
		// caller's to read: a low-entropy answer hash handed to its own owner is a
		// hash handed to whoever borrows the session, and offline guessing against
		// "mother's maiden name" is not guessing. What a reader legitimately wants
		// from it — the recovery address and whether it is confirmed — travels in the
		// two fields below.
		Metadata:  PublicMetadata(u.Metadata),
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}

	// The display form, not the canonical one. Canonicalisation folds case and
	// compatibility forms so two handles that look alike cannot both be claimed;
	// showing the reader that folded value back would silently rewrite the handle
	// they typed into a version they did not choose.
	if u.Username != nil {
		res.Username = *u.Username
	}

	if recEmail, ok := u.Metadata[metaRecoveryEmail].(string); ok {
		res.RecoveryEmail = recEmail
	}
	if recVer, ok := u.Metadata[metaRecoveryEmailVerified].(bool); ok {
		res.RecoveryEmailVerified = recVer
	}

	return res, nil
}

// UpdateProfile applies a partial update to the account's non-sensitive
// attributes and returns the resulting profile.
//
// Each supplied field is sanitised before it is stored, since name, avatar URL
// and locale are rendered back to browsers. Metadata is merged rather than
// replaced. Returns ErrUserNotFound for an unknown account, ErrUsernameInvalid or
// ErrUsernameTaken for a handle that cannot be claimed, or a wrapped validation
// error naming the offending field.
func (s *Service) UpdateProfile(ctx context.Context, userID string, req UpdateProfileRequest) (*UserProfileResponse, error) {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return nil, ErrUserNotFound
	}

	updater := client.User.UpdateOneID(userID)

	if req.Name != nil {
		// The same ceiling signup applies. A stricter limit here would refuse a name
		// the account was created with, so the owner could open their profile, save
		// nothing, and be told the value already on the page is invalid.
		cleanName, err := validator.SanitizeString(*req.Name, 1, maxNameLength)
		if err != nil {
			return nil, fmt.Errorf("invalid name: %w", err)
		}
		updater.SetName(cleanName)
	}
	if req.Username != nil {
		if err := s.applyUsername(sysCtx, u, strings.TrimSpace(*req.Username), updater); err != nil {
			return nil, err
		}
	}
	if req.AvatarURL != nil {
		cleanURL, err := validator.ValidateImageURL(*req.AvatarURL)
		if err != nil {
			return nil, fmt.Errorf("invalid avatar URL: %w", err)
		}
		updater.SetAvatarURL(cleanURL)
	}
	if req.Locale != nil {
		cleanLocale, err := validator.SanitizeString(*req.Locale, 2, 20)
		if err != nil {
			return nil, fmt.Errorf("invalid locale: %w", err)
		}
		updater.SetLocale(cleanLocale)
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	if req.Metadata != nil {
		// Refused before the merge, not filtered out of it. These keys decide whether
		// an email address counts as verified, and a caller that can write them can
		// verify an address nothing was ever sent to. Naming the key rather than
		// dropping it silently is what tells a caller storing its own "recovery_email"
		// attribute that the name is spoken for.
		if reserved := FirstReservedMetadataKey(req.Metadata); reserved != "" {
			return nil, fmt.Errorf("%w: %q is written by the engine as part of email verification and account recovery, so it cannot be set directly — choose another key for your own data", ErrReservedMetadataKey, reserved)
		}
		for k, v := range req.Metadata {
			meta[k] = v
		}
		updater.SetMetadata(meta)
	}

	updatedUser, err := updater.Save(sysCtx)
	if err != nil {
		// The lost half of the race applyUsername usually wins: the availability
		// check and the write are not one statement, so a handle claimed in between
		// arrives here as a constraint violation. Reported as the collision it is
		// rather than as an internal fault the caller cannot act on.
		if ent.IsConstraintError(err) && req.Username != nil {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("failed updating user profile: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(u.TenantID, string(updatedUser.Environment), "user.updated", map[string]interface{}{
			"user_id": updatedUser.ID,
			"email":   updatedUser.Email,
			"name":    updatedUser.Name,
		})
	}

	return s.GetProfile(ctx, userID)
}

// applyUsername stages a handle change onto updater, or its release when handle
// is empty.
//
// Both columns move together. The display column holds what the owner typed and
// the canonical column is what the unique index covers, so writing one without
// the other either loses the guarantee or leaves the two disagreeing about which
// handle the account holds.
//
// A change that folds to the account's existing canonical form skips the
// availability check rather than failing it. That case is not a no-op worth
// short-circuiting: `ada` to `Ada` folds to the same key, so nothing is being
// claimed, but the display form the owner asked for still has to be written.
func (s *Service) applyUsername(ctx context.Context, u *ent.User, handle string, updater *ent.UserUpdateOne) error {
	if handle == "" {
		// Cleared rather than set to the empty string. The canonical column is
		// covered by a unique index, and two accounts holding "" would collide on
		// it where two holding NULL do not.
		updater.ClearUsername().ClearUsernameCanonical()
		return nil
	}

	canonical, err := username.Canonical(handle)
	if err != nil {
		// Both errors are wrapped: the sentinel so the handler can classify the
		// failure, and the rule error so it can name which rule was broken without
		// a second lookup table.
		return fmt.Errorf("%w: %w", ErrUsernameInvalid, err)
	}

	if u.UsernameCanonical == nil || *u.UsernameCanonical != canonical {
		taken, err := s.authRepo.UsernamesTaken(ctx, u.TenantID, string(u.Environment), []string{canonical})
		if err != nil {
			return fmt.Errorf("checking username availability: %w", err)
		}
		if _, exists := taken[canonical]; exists {
			return ErrUsernameTaken
		}
	}

	updater.SetUsername(handle).SetUsernameCanonical(canonical)
	return nil
}

// ListSocialAccounts returns the OAuth identities linked to the account, or an
// empty slice when none are.
func (s *Service) ListSocialAccounts(ctx context.Context, userID string) ([]LinkedSocialAccount, error) {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	identities, err := client.Identity.Query().
		Where(identity.UserID(userID)).
		All(sysCtx)
	if err != nil {
		return nil, err
	}

	accounts := make([]LinkedSocialAccount, 0, len(identities))
	for _, id := range identities {
		accounts = append(accounts, LinkedSocialAccount{
			Provider:       id.Provider,
			ProviderUserID: id.ProviderUserID,
			Email:          id.Email,
			ConnectedAt:    id.CreatedAt,
		})
	}

	return accounts, nil
}

// UnlinkSocialAccount disconnects the named provider from the account.
//
// Returns ErrUserNotFound, ErrSocialNotConnected when the provider is not linked,
// or ErrCannotUnlinkLastAuth when removing it would leave the account with no way
// to sign in — no password and no other identity.
func (s *Service) UnlinkSocialAccount(ctx context.Context, userID string, providerName string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	identities, err := client.Identity.Query().
		Where(identity.UserID(userID)).
		All(sysCtx)
	if err != nil {
		return err
	}

	var targetIdentity *ent.Identity
	for _, id := range identities {
		if strings.EqualFold(id.Provider, providerName) {
			targetIdentity = id
			break
		}
	}

	if targetIdentity == nil {
		return ErrSocialNotConnected
	}

	if u.PasswordHash == "" && len(identities) <= 1 {
		return ErrCannotUnlinkLastAuth
	}

	return client.Identity.DeleteOneID(targetIdentity.ID).Exec(sysCtx)
}

// reauthenticateForDeletion re-proves the caller's identity with whatever
// credential the account holds.
//
// The order is fixed rather than a choice the caller makes: an account with a
// password is checked on the password, and only an account without one falls
// through to TOTP. Letting the request pick would mean a caller who knows the
// password could be waved through on a factor the owner had already removed, and
// vice versa.
//
// The TOTP branch needs both a verifier and an active method to be meaningful. It
// distinguishes "no code was sent" from "the code is wrong" so the client can ask
// for the code once instead of reporting a failure the user has not yet had the
// chance to cause.
func (s *Service) reauthenticateForDeletion(ctx context.Context, u *ent.User, password, totpCode string) error {
	if u.PasswordHash != "" {
		if !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
			return ErrIncorrectPassword
		}
		return nil
	}

	if s.secondFactor == nil {
		return nil
	}

	// Asked of the store rather than inferred from the request, so a caller cannot
	// skip the check by omitting the code. An account with no active method has
	// nothing to prove with and passes on the session alone.
	method, err := s.authRepo.GetActiveTOTPMethodForUser(ctx, u.ID)
	if err != nil || method == nil {
		return nil
	}

	if strings.TrimSpace(totpCode) == "" {
		return ErrTOTPRequired
	}
	if err := s.secondFactor.VerifyAdminTOTP(ctx, u.ID, strings.TrimSpace(totpCode)); err != nil {
		return ErrIncorrectTOTP
	}
	return nil
}

// DeleteAccount permanently erases the account and its dependent records, after
// re-authenticating the caller.
//
// Re-authentication uses the strongest credential the account actually holds: the
// password when it has one, otherwise a current TOTP code. An account created
// through a social provider, a passkey or a magic link has no password to re-enter,
// and accepting the session on its own would mean an unlocked laptop is enough to
// destroy someone's account. When the account holds neither a password nor an
// active TOTP method there is nothing left to re-prove, and the session stands —
// refusing there would leave the account permanently undeletable, which is a worse
// answer than the one it is guarding against.
//
// Every dependent row goes in the same transaction as the account itself: the
// foreign keys are declared with no delete action, so the database refuses to drop
// an account while one of them still points at it, and a partially cleared account
// — no sessions, no credentials, no memberships, still a row — is worse than either
// outcome. `internal/auth/retention.go` clears the same set for idle test accounts,
// so a table added to one list belongs in the other. Session activity is the one
// exception, its key being declared to cascade from the session.
//
// Organizations the account solely administers decide the outcome. One with other
// members blocks the deletion with a *SoleOrgAdminError naming it, because erasing
// the account would leave those people in a workspace nobody can rename, invite to
// or delete. One where the account is the only member is deleted alongside it,
// there being nobody left to strand and no reason to keep an empty workspace
// holding its slug.
//
// Returns ErrUserNotFound, ErrIncorrectPassword, ErrTOTPRequired, ErrIncorrectTOTP
// or *SoleOrgAdminError.
func (s *Service) DeleteAccount(ctx context.Context, tenantID, env, userID string, confirmPassword string, totpCode string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	if err := s.reauthenticateForDeletion(sysCtx, u, confirmPassword, totpCode); err != nil {
		return err
	}

	// Asked before the transaction opens, so a refusal costs nothing and the
	// blocking organizations are known before anything is written.
	soleAdminOf, err := org.SoleAdminOrganizations(sysCtx, client, userID)
	if err != nil {
		return fmt.Errorf("failed to check organization administration before deleting account: %w", err)
	}

	var blocking, abandoned []org.SoleAdminOrganization
	for _, o := range soleAdminOf {
		if o.OtherMembers > 0 {
			blocking = append(blocking, o)
			continue
		}
		abandoned = append(abandoned, o)
	}
	if len(blocking) > 0 {
		return &SoleOrgAdminError{Organizations: blocking}
	}

	tx, err := client.Tx(sysCtx)
	if err != nil {
		return fmt.Errorf("failed opening transaction to delete user account: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Named so the solo organizations can be appended below without restating the
	// literal's type.
	type dependent struct {
		name string
		del  func() (int, error)
	}

	dependents := []dependent{
		{"sessions", func() (int, error) { return tx.Session.Delete().Where(session.UserID(userID)).Exec(sysCtx) }},
		{"identities", func() (int, error) { return tx.Identity.Delete().Where(identity.UserID(userID)).Exec(sysCtx) }},
		{"two-factor methods", func() (int, error) {
			return tx.TwoFactorMethod.Delete().Where(twofactormethod.UserID(userID)).Exec(sysCtx)
		}},
		{"push devices", func() (int, error) {
			return tx.PushDevice.Delete().Where(pushdevice.UserID(userID)).Exec(sysCtx)
		}},
		{"trusted devices", func() (int, error) {
			return tx.TrustedDevice.Delete().Where(trusteddevice.UserID(userID)).Exec(sysCtx)
		}},
		{"subnet history", func() (int, error) {
			return tx.UserIpSubnetHistory.Delete().Where(useripsubnethistory.UserID(userID)).Exec(sysCtx)
		}},
		{"organization memberships", func() (int, error) {
			return tx.OrgMember.Delete().Where(orgmember.UserID(userID)).Exec(sysCtx)
		}},
		{"role assignments", func() (int, error) {
			return tx.UserRole.Delete().Where(userrole.UserID(userID)).Exec(sysCtx)
		}},
		{"recovery contacts", func() (int, error) {
			return tx.RecoveryContact.Delete().Where(recoverycontact.UserID(userID)).Exec(sysCtx)
		}},
		{"recovery requests", func() (int, error) {
			return tx.RecoveryRequest.Delete().Where(recoveryrequest.UserID(userID)).Exec(sysCtx)
		}},
		{"password history", func() (int, error) {
			return tx.UserPasswordHistory.Delete().Where(userpasswordhistory.UserID(userID)).Exec(sysCtx)
		}},
	}

	// Appended after the membership delete above, so the organization's last
	// membership is already gone by the time its own row is dropped. The count is
	// unused — the organization surface owns which tables reference an organization,
	// and this path calls into it rather than listing them a second time.
	for _, o := range abandoned {
		orgID := o.ID
		dependents = append(dependents, dependent{
			name: fmt.Sprintf("organization %q, whose only member was this account", o.Name),
			del: func() (int, error) {
				return 0, org.DeleteOrganizationWithDependents(sysCtx, tx.Client(), orgID)
			},
		})
	}

	for _, dependent := range dependents {
		if _, err := dependent.del(); err != nil {
			return fmt.Errorf("failed deleting %s of user account: %w", dependent.name, err)
		}
	}

	if err := tx.User.DeleteOneID(userID).Exec(sysCtx); err != nil {
		return fmt.Errorf("failed deleting user account: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed committing user account deletion: %w", err)
	}

	if s.webhookDispatcher != nil {
		// The organizations first: a subscriber reconciling its own roster learns the
		// workspace is gone before it learns its last member is, which is the order
		// that never leaves it holding a membership in a workspace it cannot resolve.
		for _, o := range abandoned {
			s.webhookDispatcher.Dispatch(tenantID, string(u.Environment), "org.deleted", map[string]interface{}{
				"org_id": o.ID,
				"reason": "sole_member_account_deleted",
			})
		}
		s.webhookDispatcher.Dispatch(tenantID, string(u.Environment), "user.deleted", map[string]interface{}{
			"user_id": userID,
			"email":   u.Email,
		})
	}

	return nil
}
