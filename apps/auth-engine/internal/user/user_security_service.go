/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/user_security_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: Password changes, primary/recovery email verification tokens, and recovery email lifecycle.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

// ChangePassword replaces the account password after re-authenticating the caller.
//
// The current password must verify whenever the account has one; accounts with no
// password (social-only sign-in) can set one without that step. The replacement is
// checked against the tenant password policy before it is hashed. Returns
// ErrUserNotFound, ErrIncorrectPassword, or an error naming the unmet policy
// requirements.
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

// RequestEmailChange records a pending change of the primary email address and
// mails a single-use confirmation link to the proposed address, returning the
// raw token.
//
// The link goes to the new address, not the current one, so possession of the
// address being claimed is what authorises the change. Nothing on the account
// changes until VerifyEmailChange consumes the token. Returns
// ErrEmailAlreadyInUse when the address is taken within the same tenant and
// environment, or ErrUserNotFound for an unknown account.
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

	tokenStr, tokenHash, err := newVerificationToken("emc_")
	if err != nil {
		return "", err
	}

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return "", ErrUserNotFound
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	meta[metaPendingNewEmail] = newEmail
	meta[metaPendingEmailTokenHash] = tokenHash
	meta[metaPendingEmailExpiresAt] = time.Now().Add(s.emailChangeTokenTTL()).Unix()

	err = client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return "", fmt.Errorf("failed saving pending email token: %w", err)
	}

	if s.emailProvider != nil {
		subject := "Verify your new email address"
		body := fmt.Sprintf("Click the link to verify your new email: %s/v1/client/user/email/verify?token=%s", s.verificationBaseURL(), tokenStr)
		_ = s.emailProvider.Send(sysCtx, newEmail, subject, body, body)
	}

	return tokenStr, nil
}

// VerifyEmailChange consumes an email-change token and promotes the pending
// address to the account's verified primary email.
//
// Returns ErrInvalidVerificationToken when the token is unknown, carries no
// pending address, or has passed its recorded expiry. A record whose expiry is
// missing or unreadable is rejected on the same footing, so an unverifiable
// token is never treated as a valid one.
func (s *Service) VerifyEmailChange(ctx context.Context, tokenStr string) error {
	tokenHash := hashVerificationToken(tokenStr)

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	users, err := client.User.Query().All(sysCtx)
	if err != nil {
		return err
	}

	var targetUser *ent.User
	for _, u := range users {
		if metaHash, ok := u.Metadata[metaPendingEmailTokenHash].(string); ok && metaHash == tokenHash {
			targetUser = u
			break
		}
	}

	if targetUser == nil {
		return ErrInvalidVerificationToken
	}

	expiresAt, ok := metadataUnixTime(targetUser.Metadata, metaPendingEmailExpiresAt)
	if !ok || time.Now().After(expiresAt) {
		return ErrInvalidVerificationToken
	}

	newEmail, _ := targetUser.Metadata[metaPendingNewEmail].(string)
	if newEmail == "" {
		return ErrInvalidVerificationToken
	}

	// Clearing the pending keys in the same write that sets the address is what
	// makes the token single-use.
	meta := targetUser.Metadata
	delete(meta, metaPendingNewEmail)
	delete(meta, metaPendingEmailTokenHash)
	delete(meta, metaPendingEmailExpiresAt)

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

// SetRecoveryEmail records a secondary recovery address and mails a single-use
// confirmation link to it, returning the raw token.
//
// The address is stored immediately but marked unverified, so it cannot be used
// for recovery until VerifyRecoveryEmail confirms it. Returns ErrUserNotFound for
// an unknown account.
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

	tokenStr, tokenHash, err := newVerificationToken("rec_")
	if err != nil {
		return "", err
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	meta[metaRecoveryEmail] = recoveryEmail
	meta[metaRecoveryEmailVerified] = false
	meta[metaRecoveryEmailTokenHash] = tokenHash
	meta[metaRecoveryEmailExpiresAt] = time.Now().Add(s.recoveryEmailTokenTTL()).Unix()

	err = client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return "", fmt.Errorf("failed setting recovery email: %w", err)
	}

	if s.emailProvider != nil {
		subject := "Verify your secondary recovery email"
		body := fmt.Sprintf("Click the link to verify your recovery email: %s/v1/client/user/recovery-email/verify?token=%s", s.verificationBaseURL(), tokenStr)
		_ = s.emailProvider.Send(sysCtx, recoveryEmail, subject, body, body)
	}

	return tokenStr, nil
}

// VerifyRecoveryEmail consumes a recovery-email token and marks the secondary
// address verified.
//
// Returns ErrInvalidVerificationToken when the token is unknown or has passed its
// recorded expiry. A record whose expiry is missing or unreadable is rejected on
// the same footing, so an unverifiable token is never treated as a valid one.
func (s *Service) VerifyRecoveryEmail(ctx context.Context, tokenStr string) error {
	tokenHash := hashVerificationToken(tokenStr)

	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	users, err := client.User.Query().All(sysCtx)
	if err != nil {
		return err
	}

	var targetUser *ent.User
	for _, u := range users {
		if metaHash, ok := u.Metadata[metaRecoveryEmailTokenHash].(string); ok && metaHash == tokenHash {
			targetUser = u
			break
		}
	}

	if targetUser == nil {
		return ErrInvalidVerificationToken
	}

	expiresAt, ok := metadataUnixTime(targetUser.Metadata, metaRecoveryEmailExpiresAt)
	if !ok || time.Now().After(expiresAt) {
		return ErrInvalidVerificationToken
	}

	// Clearing the token keys in the same write that flips the verified flag is
	// what makes the token single-use.
	meta := targetUser.Metadata
	meta[metaRecoveryEmailVerified] = true
	delete(meta, metaRecoveryEmailTokenHash)
	delete(meta, metaRecoveryEmailExpiresAt)

	err = client.User.UpdateOneID(targetUser.ID).
		SetMetadata(meta).
		Exec(sysCtx)
	if err != nil {
		return fmt.Errorf("failed verifying recovery email: %w", err)
	}

	return nil
}

// DeleteRecoveryEmail removes the secondary recovery address and any pending
// confirmation for it. Returns ErrUserNotFound for an unknown account.
func (s *Service) DeleteRecoveryEmail(ctx context.Context, userID string) error {
	sysCtx := privacy.NewBypassContext(ctx)
	client := s.authRepo.GetClientFactory().GetClient(sysCtx, "", "")

	u, err := client.User.Get(sysCtx, userID)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	meta := u.Metadata
	delete(meta, metaRecoveryEmail)
	delete(meta, metaRecoveryEmailVerified)
	delete(meta, metaRecoveryEmailTokenHash)
	delete(meta, metaRecoveryEmailExpiresAt)

	return client.User.UpdateOneID(userID).
		SetMetadata(meta).
		Exec(sysCtx)
}
