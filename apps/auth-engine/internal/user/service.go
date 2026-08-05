/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/service.go
 * Tier: Business Logic Layer / User Profile & Settings Service
 *
 * Description: Core business logic for User Self-Service profile updates,
 *              password changes, email verification, recovery email management,
 *              social account unlinking, and GDPR account erasure.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/trusteddevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

type Service struct {
	authRepo          *auth.Repository
	emailProvider     email.EmailProvider
	policyRepo        *policy.Repository
	webhookDispatcher *webhook.Dispatcher
}

func NewService(authRepo *auth.Repository, emailProvider email.EmailProvider, policyRepo *policy.Repository, webhookDispatcher *webhook.Dispatcher) *Service {
	return &Service{
		authRepo:          authRepo,
		emailProvider:     emailProvider,
		policyRepo:        policyRepo,
		webhookDispatcher: webhookDispatcher,
	}
}

// GetProfile retrieves the full profile and metadata of an authenticated user.
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

	if recEmail, ok := u.Metadata["recovery_email"].(string); ok {
		res.RecoveryEmail = recEmail
	}
	if recVer, ok := u.Metadata["recovery_email_verified"].(bool); ok {
		res.RecoveryEmailVerified = recVer
	}

	return res, nil
}

// UpdateProfile updates non-sensitive user attributes (name, avatar, locale, custom metadata).
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

// ChangePassword allows an authenticated user to change their password with step-up verification.
func (s *Service) ChangePassword(ctx context.Context, tenantID, env, userID string, currentPassword, newPassword string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	if u.PasswordHash != "" {
		if !crypto.VerifyPasswordArgon2id(currentPassword, u.PasswordHash) {
			return ErrIncorrectPassword
		}
	}

	if s.policyRepo != nil {
		pol, err := s.policyRepo.GetPasswordPolicy(sysCtx, tenantID)
		if err == nil {
			missing := policy.ValidatePassword(pol, newPassword)
			if len(missing) > 0 {
				return fmt.Errorf("password does not meet policy requirements: missing %v", missing)
			}
		}
	}

	newHash, err := crypto.HashPasswordArgon2id(newPassword)
	if err != nil {
		return fmt.Errorf("failed hashing password: %w", err)
	}

	err = client.User.UpdateOneID(userID).
		SetPasswordHash(newHash).
		Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed saving updated password hash: %w", err)
	}

	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(tenantID, "password.changed", map[string]interface{}{
			"user_id": userID,
			"email":   u.Email,
		})
	}

	return nil
}

// RequestEmailChange sends a single-use token to the new email address for verification.
func (s *Service) RequestEmailChange(ctx context.Context, tenantID, env, userID, newEmail string) (string, error) {
	if err := validator.ValidateEmail(newEmail); err != nil {
		return "", err
	}
	newEmail = strings.TrimSpace(strings.ToLower(newEmail))

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	exists, err := client.User.Query().
		Where(user.TenantID(tenantID), user.EnvironmentEQ(user.Environment(env)), user.Email(newEmail)).
		Exist(sysCtx)
	if err != nil {
		return "", err
	}
	if exists {
		return "", ErrEmailAlreadyInUse
	}

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed generating random token: %w", err)
	}
	tokenStr := "emc_" + hex.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(hash[:])

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return "", ErrUserNotFound
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	meta["pending_new_email"] = newEmail
	meta["pending_email_token_hash"] = tokenHash
	meta["pending_email_expires_at"] = time.Now().Add(1 * time.Hour).Unix()

	err = client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return "", fmt.Errorf("failed saving pending email token: %w", err)
	}

	if s.emailProvider != nil {
		subject := "Verify your new email address"
		body := fmt.Sprintf("Click the link to verify your new email: http://localhost:8080/v1/client/user/email/verify?token=%s", tokenStr)
		_ = s.emailProvider.Send(sysCtx, newEmail, subject, body, body)
	}

	return tokenStr, nil
}

// VerifyEmailChange completes the primary email change flow.
func (s *Service) VerifyEmailChange(ctx context.Context, tokenStr string) error {
	hash := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(hash[:])

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	users, err := client.User.Query().All(sysCtx)
	if err != nil {
		return err
	}

	var targetUser *ent.User
	for _, u := range users {
		if metaHash, ok := u.Metadata["pending_email_token_hash"].(string); ok && metaHash == tokenHash {
			targetUser = u
			break
		}
	}

	if targetUser == nil {
		return ErrInvalidVerificationToken
	}

	newEmail, _ := targetUser.Metadata["pending_new_email"].(string)
	if newEmail == "" {
		return ErrInvalidVerificationToken
	}

	meta := targetUser.Metadata
	delete(meta, "pending_new_email")
	delete(meta, "pending_email_token_hash")
	delete(meta, "pending_email_expires_at")

	err = client.User.UpdateOneID(targetUser.ID).
		SetEmail(newEmail).
		SetEmailVerified(true).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed updating primary email: %w", err)
	}

	return nil
}

// SetRecoveryEmail initiates secondary recovery email registration.
func (s *Service) SetRecoveryEmail(ctx context.Context, tenantID, env, userID, recoveryEmail string) (string, error) {
	if err := validator.ValidateEmail(recoveryEmail); err != nil {
		return "", err
	}
	recoveryEmail = strings.TrimSpace(strings.ToLower(recoveryEmail))

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, tenantID, env)

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return "", ErrUserNotFound
	}

	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed generating random token: %w", err)
	}
	tokenStr := "rec_" + hex.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(hash[:])

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	meta["recovery_email"] = recoveryEmail
	meta["recovery_email_verified"] = false
	meta["recovery_email_token_hash"] = tokenHash
	meta["recovery_email_expires_at"] = time.Now().Add(24 * time.Hour).Unix()

	err = client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return "", fmt.Errorf("failed setting recovery email: %w", err)
	}

	if s.emailProvider != nil {
		subject := "Verify your secondary recovery email"
		body := fmt.Sprintf("Click the link to verify your recovery email: http://localhost:8080/v1/client/user/recovery-email/verify?token=%s", tokenStr)
		_ = s.emailProvider.Send(sysCtx, recoveryEmail, subject, body, body)
	}

	return tokenStr, nil
}

// VerifyRecoveryEmail completes secondary recovery email verification.
func (s *Service) VerifyRecoveryEmail(ctx context.Context, tokenStr string) error {
	hash := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(hash[:])

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	users, err := client.User.Query().All(sysCtx)
	if err != nil {
		return err
	}

	var targetUser *ent.User
	for _, u := range users {
		if metaHash, ok := u.Metadata["recovery_email_token_hash"].(string); ok && metaHash == tokenHash {
			targetUser = u
			break
		}
	}

	if targetUser == nil {
		return ErrInvalidVerificationToken
	}

	meta := targetUser.Metadata
	meta["recovery_email_verified"] = true
	delete(meta, "recovery_email_token_hash")
	delete(meta, "recovery_email_expires_at")

	err = client.User.UpdateOneID(targetUser.ID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed verifying recovery email: %w", err)
	}

	return nil
}

// DeleteRecoveryEmail removes the secondary recovery email from user profile.
func (s *Service) DeleteRecoveryEmail(ctx context.Context, userID string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	meta := u.Metadata
	delete(meta, "recovery_email")
	delete(meta, "recovery_email_verified")
	delete(meta, "recovery_email_token_hash")
	delete(meta, "recovery_email_expires_at")

	return client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
}

// ListSocialAccounts lists connected OAuth identities for a user.
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

// UnlinkSocialAccount disconnects a social provider identity from the account.
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

	// Safety check: ensure user has password OR at least one other social identity
	if u.PasswordHash == "" && len(identities) <= 1 {
		return ErrCannotUnlinkLastAuth
	}

	return client.Identity.DeleteOneID(targetIdentity.ID).Exec(sysCtx)
}

// DeleteAccount performs self-service account deletion (GDPR right to erasure).
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

	// Purge related child records before deleting User to prevent FK constraint failures
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
