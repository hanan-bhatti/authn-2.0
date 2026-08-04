/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/guardian_service.go
 * Tier: Internal Feature Package / Guardian Management Service
 *
 * Description: Business logic for trusted guardian pre-enrollment, 1-5 flexible majority threshold,
 *              zero-knowledge share distribution, and Re-Key/Re-Split protocol on guardian revocation.
 *
 * Security Notice:
 *   - Raw shares exist in memory ONLY during Split computation and are ZEROIZED immediately.
 *   - Database persists ONLY SHA-256 hashes of shares.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

var (
	ErrMaxGuardiansExceeded = errors.New("cannot enroll more than 5 trusted guardians per account")
	ErrGuardianNotFound     = errors.New("guardian contact not found")
	ErrInvalidInviteToken   = errors.New("invalid or expired guardian invitation token")
)

// GuardianDTO defines the public guardian object returned to authenticated clients.
type GuardianDTO struct {
	ID            string    `json:"id"`
	GuardianEmail string    `json:"guardian_email"`
	GuardianName  string    `json:"guardian_name"`
	ShareIndex    int       `json:"share_index"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

// InviteGuardianInput defines payload for enrolling a single guardian.
type InviteGuardianInput struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// InviteGuardiansResponse returns invitation results for client distribution.
type InviteGuardiansResponse struct {
	EnrolledCount int           `json:"enrolled_count"`
	ThresholdK    int           `json:"threshold_k"`
	Guardians     []GuardianDTO `json:"guardians"`
	InviteURLs    []string      `json:"invite_urls,omitempty"`
}

// ServiceGuardianExtensions defines guardian management methods on Auth Service.
type GuardianService struct {
	repo       *Repository
	policyRepo *policy.Repository
}

// NewGuardianService constructs a new GuardianService instance.
func NewGuardianService(repo *Repository, policyRepo *policy.Repository) *GuardianService {
	return &GuardianService{
		repo:       repo,
		policyRepo: policyRepo,
	}
}

// InviteGuardians adds trusted guardians, generates Shamir shares, and issues zero-knowledge invite tokens.
func (s *GuardianService) InviteGuardians(ctx context.Context, userID string, inputs []InviteGuardianInput, baseURL string) (*InviteGuardiansResponse, error) {
	if len(inputs) == 0 {
		return nil, errors.New("must provide at least one guardian invitation input")
	}

	u, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed fetching user for guardian invitation: %w", err)
	}

	var recPolicy policy.RecoveryPolicy
	if s.policyRepo != nil {
		recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID)
	} else {
		recPolicy = policy.DefaultRecoveryPolicy()
	}

	if !recPolicy.GuardiansEnabled {
		return nil, errors.New("guardian account recovery is disabled for this tenant")
	}

	existing, err := s.repo.GetRecoveryContactsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed fetching existing guardians: %w", err)
	}

	totalN := len(existing) + len(inputs)
	if totalN > recPolicy.MaxGuardians {
		return nil, fmt.Errorf("cannot exceed maximum allowed limit of %d guardian(s) per tenant policy", recPolicy.MaxGuardians)
	}
	if totalN < recPolicy.MinGuardians {
		return nil, fmt.Errorf("must enroll at least %d guardian(s) per tenant policy", recPolicy.MinGuardians)
	}

	thresholdK, err := CalculateThreshold(totalN)
	if err != nil {
		return nil, err
	}

	// Generate Master Recovery Secret M
	masterSecret, err := GenerateMasterSecret()
	if err != nil {
		return nil, err
	}
	defer Zeroize(masterSecret)

	// Split Master Secret M into totalN shares
	shares, err := SplitSecret(masterSecret, totalN, thresholdK)
	if err != nil {
		return nil, fmt.Errorf("failed splitting secret: %w", err)
	}
	defer func() {
		for _, s := range shares {
			Zeroize(s)
		}
	}()

	// Re-key existing guardians with new shares (indices 1 .. len(existing))
	for i, contact := range existing {
		shareIdx := i + 1
		sHash := HashSecret(shares[i])
		if err := s.repo.UpdateRecoveryContactShare(ctx, contact.ID, shareIdx, sHash); err != nil {
			return nil, fmt.Errorf("failed updating share for existing guardian %s: %w", contact.ID, err)
		}
	}

	// Create new guardian entries for inputs (indices len(existing)+1 .. totalN)
	newGuardians := make([]GuardianDTO, 0, len(inputs))
	inviteURLs := make([]string, 0, len(inputs))

	for i, input := range inputs {
		shareIdx := len(existing) + i + 1
		rawShare := shares[len(existing)+i]
		sHash := HashSecret(rawShare)

		// Generate random invitation token
		rawToken := make([]byte, 32)
		if _, err := rand.Read(rawToken); err != nil {
			return nil, fmt.Errorf("failed generating invite token: %w", err)
		}
		rawTokenHex := hex.EncodeToString(rawToken)
		inviteHash := HashSecret([]byte(rawTokenHex))
		expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7-day invitation expiry

		contact, err := s.repo.CreateRecoveryContact(ctx, userID, input.Email, input.Name, shareIdx, sHash, inviteHash, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("failed creating guardian %s: %w", input.Email, err)
		}

		newGuardians = append(newGuardians, GuardianDTO{
			ID:            contact.ID,
			GuardianEmail: contact.GuardianEmail,
			GuardianName:  contact.GuardianName,
			ShareIndex:    contact.ShareIndex,
			Status:        string(contact.Status),
			CreatedAt:     contact.CreatedAt,
		})

		// Construct URL with token in fragment (zero-knowledge)
		inviteURL := fmt.Sprintf("%s/recovery/guardian/accept?id=%s#token=%s", baseURL, contact.ID, rawTokenHex)
		inviteURLs = append(inviteURLs, inviteURL)
	}

	return &InviteGuardiansResponse{
		EnrolledCount: totalN,
		ThresholdK:    thresholdK,
		Guardians:     newGuardians,
		InviteURLs:    inviteURLs,
	}, nil
}

// AcceptGuardianInvite confirms a pending guardian invitation.
func (s *GuardianService) AcceptGuardianInvite(ctx context.Context, contactID, rawTokenHex string) error {
	contact, err := s.repo.GetRecoveryContactByID(ctx, contactID)
	if err != nil || contact == nil {
		return ErrGuardianNotFound
	}

	if contact.Status != recoverycontact.StatusPendingInvite {
		return errors.New("guardian invitation is no longer pending")
	}

	if contact.InvitationExpiresAt != nil && time.Now().After(*contact.InvitationExpiresAt) {
		return errors.New("guardian invitation token has expired")
	}

	expectedHash := HashSecret([]byte(rawTokenHex))
	if contact.InvitationTokenHash == nil || *contact.InvitationTokenHash != expectedHash {
		return ErrInvalidInviteToken
	}

	return s.repo.UpdateRecoveryContactStatus(ctx, contactID, recoverycontact.StatusActive)
}

// ListGuardians returns all guardians enrolled by the user.
func (s *GuardianService) ListGuardians(ctx context.Context, userID string) ([]GuardianDTO, error) {
	contacts, err := s.repo.GetRecoveryContactsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	dtos := make([]GuardianDTO, len(contacts))
	for i, c := range contacts {
		dtos[i] = GuardianDTO{
			ID:            c.ID,
			GuardianEmail: c.GuardianEmail,
			GuardianName:  c.GuardianName,
			ShareIndex:    c.ShareIndex,
			Status:        string(c.Status),
			CreatedAt:     c.CreatedAt,
		}
	}
	return dtos, nil
}

// RevokeGuardian deletes a guardian and executes the Re-Key & Re-Split Protocol for remaining guardians.
func (s *GuardianService) RevokeGuardian(ctx context.Context, userID, contactID string) error {
	target, err := s.repo.GetRecoveryContactByID(ctx, contactID)
	if err != nil || target == nil || target.UserID != userID {
		return ErrGuardianNotFound
	}

	if err := s.repo.DeleteRecoveryContact(ctx, contactID); err != nil {
		return err
	}

	// Fetch remaining guardians
	remaining, err := s.repo.GetRecoveryContactsByUser(ctx, userID)
	if err != nil {
		return err
	}

	if len(remaining) == 0 {
		return nil // All guardians removed
	}

	// Re-Key & Re-Split Protocol for N_new remaining guardians
	newN := len(remaining)
	newK, err := CalculateThreshold(newN)
	if err != nil {
		return err
	}

	masterSecret, err := GenerateMasterSecret()
	if err != nil {
		return err
	}
	defer Zeroize(masterSecret)

	shares, err := SplitSecret(masterSecret, newN, newK)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range shares {
			Zeroize(s)
		}
	}()

	// Update share indices & hashes for remaining guardians
	for i, c := range remaining {
		newIdx := i + 1
		sHash := HashSecret(shares[i])
		if err := s.repo.UpdateRecoveryContactShare(ctx, c.ID, newIdx, sHash); err != nil {
			return fmt.Errorf("failed updating re-split share for guardian %s: %w", c.ID, err)
		}
	}

	return nil
}
