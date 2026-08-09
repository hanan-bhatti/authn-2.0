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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/trusteddevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

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
		Metadata:      u.Metadata,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
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
// replaced. Returns ErrUserNotFound for an unknown account, or a wrapped
// validation error naming the offending field.
func (s *Service) UpdateProfile(ctx context.Context, userID string, req UpdateProfileRequest) (*UserProfileResponse, error) {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return nil, ErrUserNotFound
	}

	updater := client.User.UpdateOneID(userID)

	if req.Name != nil {
		cleanName, err := validator.SanitizeString(*req.Name, 1, 100)
		if err != nil {
			return nil, fmt.Errorf("invalid name: %w", err)
		}
		updater.SetName(cleanName)
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
		for k, v := range req.Metadata {
			meta[k] = v
		}
		updater.SetMetadata(meta)
	}

	updatedUser, err := updater.Save(sysCtx)
	if err != nil {
		return nil, fmt.Errorf("failed updating user profile: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(u.TenantID, "user.updated", map[string]interface{}{
			"user_id": updatedUser.ID,
			"email":   updatedUser.Email,
			"name":    updatedUser.Name,
		})
	}

	return s.GetProfile(ctx, userID)
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

// DeleteAccount permanently erases the account and its dependent records, after
// re-authenticating the caller.
//
// The password must verify whenever the account has one. Child records are purged
// before the user row so foreign keys never block the deletion, and because
// leaving sessions or credentials behind would outlive the account they belong
// to. Returns ErrUserNotFound or ErrIncorrectPassword.
func (s *Service) DeleteAccount(ctx context.Context, tenantID, env, userID string, confirmPassword string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	if u.PasswordHash != "" {
		if !crypto.VerifyPasswordArgon2id(confirmPassword, u.PasswordHash) {
			return ErrIncorrectPassword
		}
	}

	_, _ = client.Session.Delete().Where(session.UserID(userID)).Exec(sysCtx)
	_, _ = client.OrgMember.Delete().Where(orgmember.UserID(userID)).Exec(sysCtx)
	_, _ = client.TwoFactorMethod.Delete().Where(twofactormethod.UserID(userID)).Exec(sysCtx)
	_, _ = client.TrustedDevice.Delete().Where(trusteddevice.UserID(userID)).Exec(sysCtx)
	_, _ = client.Identity.Delete().Where(identity.UserID(userID)).Exec(sysCtx)
	_, _ = client.RecoveryContact.Delete().Where(recoverycontact.UserID(userID)).Exec(sysCtx)

	err = client.User.DeleteOneID(userID).Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed deleting user account: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(tenantID, "user.deleted", map[string]interface{}{
			"user_id": userID,
			"email":   u.Email,
		})
	}

	return nil
}
