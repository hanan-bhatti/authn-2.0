/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/guardian_service.go
 * Tier: Internal Feature Package / Guardian Management Service
 *
 * Description: Business logic for trusted guardian pre-enrollment, 1-5 flexible majority threshold,
 *              and one-time share distribution over the invitation link.
 *
 * Security Notice:
 *   - A raw share exists in memory only long enough to be hashed and encoded into the
 *     one-time link, then is ZEROIZED.
 *   - Database persists ONLY SHA-256 hashes of shares, so a stolen dump proves nothing.
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

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

var (
	ErrMaxGuardiansExceeded = errors.New("cannot enroll more than 5 trusted guardians per account")
	ErrGuardianNotFound     = errors.New("guardian contact not found")
	ErrInvalidInviteToken   = errors.New("invalid or expired guardian invitation token")

	// ErrInvalidGuardianShare reports an acceptance whose share does not match the one issued with
	// the invitation. In practice that is a link copied without its full fragment, so the message
	// points at the link rather than at the guardian.
	ErrInvalidGuardianShare = errors.New("this invitation link is incomplete — open the full link exactly as it was sent")

	// ErrGuardianInviteNotPending reports an acceptance for a guardian who is already active, or
	// whose invitation was withdrawn. It is separate from ErrInvalidInviteToken because the common
	// cause is a guardian reopening their own link to find their share again, and telling that
	// person their link is invalid would send them chasing a replacement they do not need.
	ErrGuardianInviteNotPending = errors.New("this invitation has already been accepted")

	// ErrGuardianInviteExpired reports an invitation past its window. Only the account holder can
	// issue another, so the message points the guardian back at them.
	ErrGuardianInviteExpired = errors.New("this invitation has expired — ask for a new link from the person who invited you")
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

// GuardianInviteLink is one guardian's link, paired with the person it is for.
//
// Paired rather than returned as a bare list of URLs: every link differs only in two
// long hex strings, so a client handed five of them and a separate roster has no way
// to tell which belongs to whom, and a link sent to the wrong guardian hands that
// person someone else's share.
//
// The link is shown once. Its share exists nowhere else — the engine keeps only a
// digest — so a client that discards this response has destroyed the guardian's half
// of the proof and the only remedy is to remove and re-invite them.
type GuardianInviteLink struct {
	ContactID     string `json:"contact_id"`
	GuardianEmail string `json:"guardian_email"`
	GuardianName  string `json:"guardian_name"`
	URL           string `json:"url"`
}

// InviteGuardiansResponse returns invitation results for client distribution.
//
// ThresholdK is a majority of EnrolledCount, which counts guardians who have not accepted
// yet. It is therefore the threshold the roster will reach rather than the one in force:
// SubmitGuardianShareProof derives k from the active guardians alone, because a guardian
// still holding an unopened invitation cannot submit anything and counting them would make
// recovery impossible until every last person clicked their link.
type InviteGuardiansResponse struct {
	EnrolledCount int                  `json:"enrolled_count"`
	ThresholdK    int                  `json:"threshold_k"`
	Guardians     []GuardianDTO        `json:"guardians"`
	Invites       []GuardianInviteLink `json:"invites"`
}

// guardianAcceptURL builds the link a newly invited guardian opens.
//
// Both secrets ride in the URL fragment, which a browser never sends to a server.
// That keeps them out of the engine's access log, out of any intermediary's, and out
// of the Referer header the accept page would otherwise leak them through. The
// account holder does receive them, in this response, because they are the one who
// delivers the links — the fragment protects the guardian's hop, not the owner's.
//
// token proves the link came from an invitation the account holder created. share is
// the guardian's half of the recovery proof; the engine stores only its digest, so
// this is the single moment it can be handed over.
func guardianAcceptURL(baseURL, contactID, tokenHex, shareHex string) string {
	return fmt.Sprintf("%s/recovery/guardian/accept?id=%s#token=%s&share=%s",
		baseURL, contactID, tokenHex, shareHex)
}

// nextShareIndex returns the lowest enrollment slot not already taken.
//
// Slots are unique per account in the database, and they are no longer contiguous:
// revoking a guardian leaves a hole rather than renumbering the rest, because
// renumbering would rewrite rows whose shares are still in their guardians' hands.
// Filling the lowest hole keeps the numbers small and keeps the insert from
// colliding with a survivor.
func nextShareIndex(existing []*ent.RecoveryContact) int {
	taken := make(map[int]bool, len(existing))
	for _, c := range existing {
		taken[c.ShareIndex] = true
	}
	for i := 1; ; i++ {
		if !taken[i] {
			return i
		}
	}
}

// ServiceGuardianExtensions defines guardian management methods on Auth Service.
type GuardianService struct {
	repo       *Repository
	policyRepo *policy.Repository
	// cfg supplies the guardian invitation lifetime. Nil falls back to
	// defaultGuardianInviteTTL.
	cfg *config.Config
}

// NewGuardianService constructs a new GuardianService instance.
//
// cfg is variadic so the package's own tests can construct a service without
// one; application code passes it. Without it the invitation lifetime falls back
// to defaultGuardianInviteTTL.
func NewGuardianService(repo *Repository, policyRepo *policy.Repository, cfg ...*config.Config) *GuardianService {
	s := &GuardianService{
		repo:       repo,
		policyRepo: policyRepo,
	}
	if len(cfg) > 0 {
		s.cfg = cfg[0]
	}
	return s
}

// defaultGuardianInviteTTL bounds how long a guardian invitation stays
// redeemable when no configuration was supplied. It mirrors the default
// config.Load installs for InvitationTTL.
const defaultGuardianInviteTTL = 7 * 24 * time.Hour

// invitationTTL returns how long a newly issued guardian invitation remains
// redeemable.
func (s *GuardianService) invitationTTL() time.Duration {
	if s.cfg != nil && s.cfg.InvitationTTL > 0 {
		return s.cfg.InvitationTTL
	}
	return defaultGuardianInviteTTL
}

// InviteGuardians adds trusted guardians and issues one single-use link each, carrying
// that guardian's share.
//
// Each guardian holds an independent secret rather than a point on a shared polynomial.
// Consensus is proven by counting how many distinct active guardians produced a secret
// matching their stored digest, which is what SubmitGuardianShareProof does; no master
// secret is ever reassembled, so splitting one would buy nothing and would cost every
// guardian their saved share each time the roster changed.
//
// Independent secrets are why enrolling one guardian leaves the others alone. Adding a
// sixth person does not reach into the five shares already sitting in five inboxes.
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
		recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID, string(u.Environment))
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

	newGuardians := make([]GuardianDTO, 0, len(inputs))
	invites := make([]GuardianInviteLink, 0, len(inputs))

	// Grown as rows are created so that two guardians in one request cannot be handed
	// the same slot: the database would refuse the second insert, leaving the first
	// enrolled and the caller holding a partial roster.
	enrolled := append([]*ent.RecoveryContact(nil), existing...)

	for _, input := range inputs {
		rawShare, err := GenerateGuardianShare()
		if err != nil {
			return nil, fmt.Errorf("failed generating guardian share: %w", err)
		}
		shareHex := hex.EncodeToString(rawShare)
		sHash := HashSecret(rawShare)
		Zeroize(rawShare)

		rawToken := make([]byte, 32)
		if _, err := rand.Read(rawToken); err != nil {
			return nil, fmt.Errorf("failed generating invite token: %w", err)
		}
		rawTokenHex := hex.EncodeToString(rawToken)
		inviteHash := HashSecret([]byte(rawTokenHex))
		expiresAt := time.Now().Add(s.invitationTTL())

		contact, err := s.repo.CreateRecoveryContact(ctx, userID, input.Email, input.Name,
			nextShareIndex(enrolled), sHash, inviteHash, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("failed creating guardian %s: %w", input.Email, err)
		}
		enrolled = append(enrolled, contact)

		newGuardians = append(newGuardians, GuardianDTO{
			ID:            contact.ID,
			GuardianEmail: contact.GuardianEmail,
			GuardianName:  contact.GuardianName,
			ShareIndex:    contact.ShareIndex,
			Status:        string(contact.Status),
			CreatedAt:     contact.CreatedAt,
		})

		invites = append(invites, GuardianInviteLink{
			ContactID:     contact.ID,
			GuardianEmail: contact.GuardianEmail,
			GuardianName:  contact.GuardianName,
			URL:           guardianAcceptURL(baseURL, contact.ID, rawTokenHex, shareHex),
		})
	}

	return &InviteGuardiansResponse{
		EnrolledCount: totalN,
		ThresholdK:    thresholdK,
		Guardians:     newGuardians,
		Invites:       invites,
	}, nil
}

// AcceptGuardianInvite confirms a pending guardian invitation.
//
// Both halves of the link are checked: the token proves the guardian opened a link the account
// holder issued, and the share proves they still hold the secret that link carried. Only the token
// is strictly needed to mark the row active, but a guardian whose share was lost or truncated in
// transit is no guardian at all, and the failure would otherwise surface during a lockout — the one
// moment it cannot be repaired. Checking it here turns that into an error the account holder can
// still act on by re-inviting.
func (s *GuardianService) AcceptGuardianInvite(ctx context.Context, contactID, rawTokenHex, shareHex string) error {
	contact, err := s.repo.GetRecoveryContactByID(ctx, contactID)
	if err != nil || contact == nil {
		return ErrGuardianNotFound
	}

	if contact.Status != recoverycontact.StatusPendingInvite {
		return ErrGuardianInviteNotPending
	}

	if contact.InvitationExpiresAt != nil && time.Now().After(*contact.InvitationExpiresAt) {
		return ErrGuardianInviteExpired
	}

	expectedHash := HashSecret([]byte(rawTokenHex))
	if contact.InvitationTokenHash == nil || *contact.InvitationTokenHash != expectedHash {
		return ErrInvalidInviteToken
	}

	shareBytes, err := hex.DecodeString(shareHex)
	if err != nil || HashSecret(shareBytes) != contact.ShareHash {
		return ErrInvalidGuardianShare
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

// RevokeGuardian removes one guardian from the account.
//
// Deleting the row is the whole revocation. A revoked guardian's share can no longer
// match anything, because SubmitGuardianShareProof only ever compares against rows that
// are still present and active, and the survivors' shares are unrelated to the deleted
// one — knowing it reveals nothing about theirs.
//
// The survivors are deliberately left alone. Re-issuing their shares would invalidate
// every copy already saved by a guardian, and any guardian who missed the re-issue
// would be silently unable to help during a recovery — a failure discovered at the one
// moment it cannot be repaired.
//
// The threshold is not stored; it is derived from the live roster wherever it is needed,
// so removing the third of three guardians lowers the bar from 2 to 2 of 2 by itself.
func (s *GuardianService) RevokeGuardian(ctx context.Context, userID, contactID string) error {
	target, err := s.repo.GetRecoveryContactByID(ctx, contactID)
	if err != nil || target == nil || target.UserID != userID {
		return ErrGuardianNotFound
	}

	return s.repo.DeleteRecoveryContact(ctx, contactID)
}
