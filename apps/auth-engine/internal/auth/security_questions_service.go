/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/security_questions_service.go
 * Tier: Internal Feature Package / Account Recovery Factor
 *
 * Description: Enrollment, roster reads and answer verification for security questions, the
 *              last-resort account recovery factor. Holds the answer normalization rules, the
 *              Argon2id storage format, and the bounds on an enrollable set.
 *
 * Security Notice:
 *   - Answers are stored only as Argon2id digests of their normalized form, never in the clear,
 *     and the digests are never returned to any caller.
 *   - The roster lives under a metadata key no client may read or write; the profile surfaces in
 *     internal/user and internal/useradmin refuse the key by name and strip it from reads.
 *   - Every enrolled question must be answered correctly, and a failed attempt counts against the
 *     same recovery lockout schedule as a failed old-password proof.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/validator"
)

// securityQuestionsMetadataKey is the account metadata entry holding the enrolled
// roster.
//
// The literal is repeated in internal/user, which reserves it against client
// writes. It cannot be shared: internal/user imports this package, so the
// dependency cannot run the other way. A change here is a change there.
const securityQuestionsMetadataKey = "security_questions"

// Bounds on an enrollable set. They are engine limits rather than tenant policy:
// the tenant toggle decides whether the method may be used at all, and a tenant
// permitted to lower the count to one would be turning a credential back into a
// piece of trivia.
const (
	// minSecurityQuestions is the smallest enrollable set. A single fact is one
	// somebody else may also know; three demanded together is the least that
	// behaves like a credential.
	minSecurityQuestions = 3
	// maxSecurityQuestions bounds the set. Every answer is hashed on enrollment and
	// verified on every attempt, and each verification is a deliberately expensive
	// Argon2id computation.
	maxSecurityQuestions = 5
	// maxSecurityQuestionRunes bounds a prompt, which is stored and rendered back.
	maxSecurityQuestionRunes = 200
	// minSecurityAnswerRunes is counted after normalization, so it bounds what is
	// actually hashed rather than what was typed.
	minSecurityAnswerRunes = 3
	// maxSecurityAnswerRunes bounds an answer on the same footing as a prompt.
	maxSecurityAnswerRunes = 100
)

var (
	// ErrSecurityQuestionCount reports a set that is too small or too large to
	// enroll. Its text names both bounds, because a caller told only that the count
	// is wrong cannot tell which way.
	ErrSecurityQuestionCount = fmt.Errorf("enroll between %d and %d security questions, each with its own answer", minSecurityQuestions, maxSecurityQuestions)

	// ErrSecurityQuestionInvalid reports a prompt or answer that cannot be stored.
	// It is always wrapped so the message names what was wrong with which entry.
	ErrSecurityQuestionInvalid = errors.New("security question could not be saved")

	// ErrNoSecurityQuestions reports that the account has none enrolled. Returned
	// from the roster read, where it is an ordinary answer, and from the proof,
	// where it is a refusal.
	ErrNoSecurityQuestions = errors.New("no security questions are enrolled on this account")
)

// SecurityQuestionInput is one question and its answer as submitted at enrollment.
type SecurityQuestionInput struct {
	// Question is the prompt shown to whoever is recovering the account.
	Question string `json:"question"`
	// Answer is hashed and discarded. It is never stored or returned in the clear.
	Answer string `json:"answer"`
}

// SecurityQuestionDTO is one enrolled question as it is read back: the prompt and
// the ID that addresses it, and nothing about the answer.
type SecurityQuestionDTO struct {
	// ID addresses this question in an answers map at proof time. It is stable
	// across reads and is not derived from the prompt, so re-wording a question
	// does not silently change what an answer is keyed to.
	ID string `json:"id"`
	// Question is the prompt as the account holder wrote it.
	Question string `json:"question"`
}

// storedSecurityQuestion is one enrolled question as it is persisted in the
// account's metadata.
type storedSecurityQuestion struct {
	ID         string `json:"id"`
	Question   string `json:"question"`
	AnswerHash string `json:"answer_hash"`
}

// normalizeSecurityAnswer folds an answer to the form that is hashed and compared.
//
// The same person types the same answer months apart, from a different device,
// under the stress of being locked out. Case, leading and trailing space, and runs
// of space between words all vary between one typing and the next without the
// person meaning anything different, so a byte-exact comparison rejects answers
// that are correct. Unicode composition varies the same way and is folded by the
// hashing layer, which applies NFKC to both sides.
//
// Each fold costs entropy from an answer that has little to begin with. That is
// the trade this method is, and it is why the method is offered only when nothing
// stronger is available.
func normalizeSecurityAnswer(answer string) string {
	// Fields splits on any run of Unicode space and drops empty results, so this
	// collapses internal runs and trims the ends in one pass.
	return strings.ToLower(strings.Join(strings.Fields(answer), " "))
}

// decodeSecurityQuestions reads the stored roster out of an account's metadata bag.
//
// The value makes a JSON round trip through the database, so it arrives as
// []interface{} of map[string]interface{} rather than as the struct that was
// written. Re-marshalling is what turns it back, and it is also the check: a value
// under this key that is not a roster fails to decode rather than being read as a
// partial one.
//
// It returns an empty slice and no error when the key is absent, which is the
// ordinary state of an account that never enrolled.
func decodeSecurityQuestions(meta map[string]interface{}) ([]storedSecurityQuestion, error) {
	if meta == nil {
		return nil, nil
	}
	raw, exists := meta[securityQuestionsMetadataKey]
	if !exists || raw == nil {
		return nil, nil
	}

	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed re-encoding stored security questions: %w", err)
	}

	var stored []storedSecurityQuestion
	if err := json.Unmarshal(encoded, &stored); err != nil {
		return nil, fmt.Errorf("failed decoding stored security questions: %w", err)
	}

	// An entry without a hash cannot be verified against, so it is not a question —
	// it is a prompt that would be accepted on any answer. Dropping it here is what
	// keeps a hand-edited or half-written roster from becoming a bypass.
	usable := make([]storedSecurityQuestion, 0, len(stored))
	for _, q := range stored {
		if q.ID == "" || q.Question == "" || q.AnswerHash == "" {
			continue
		}
		usable = append(usable, q)
	}
	return usable, nil
}

// ListSecurityQuestions returns the prompts enrolled on an account, in the order
// they were saved, without anything about their answers.
//
// It returns ErrNoSecurityQuestions when none are enrolled, so a settings page can
// tell "not set up" from "set up" without inspecting an empty list.
func (s *RecoveryService) ListSecurityQuestions(ctx context.Context, userID string) ([]SecurityQuestionDTO, error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	u, err := client.User.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	stored, err := decodeSecurityQuestions(u.Metadata)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 {
		return nil, ErrNoSecurityQuestions
	}

	dtos := make([]SecurityQuestionDTO, len(stored))
	for i, q := range stored {
		dtos[i] = SecurityQuestionDTO{ID: q.ID, Question: q.Question}
	}
	return dtos, nil
}

// SetSecurityQuestions replaces the account's roster with inputs and returns the
// prompts as they were saved.
//
// The whole set is replaced rather than merged. A partial update would let a
// caller add a question it knows the answer to while leaving the others in place,
// and the proof demands every answer — so the added one would be the only new
// thing an attacker had to know, and the set would get weaker with each addition
// rather than stronger.
//
// Answers are normalized, hashed with Argon2id and discarded. Prompts are
// sanitised on the same terms as any other stored string that is rendered back.
//
// Returns ErrSecurityQuestionCount for a set outside the enrollable bounds, or a
// wrapped ErrSecurityQuestionInvalid naming the entry and the rule it broke.
func (s *RecoveryService) SetSecurityQuestions(ctx context.Context, userID string, inputs []SecurityQuestionInput) ([]SecurityQuestionDTO, error) {
	if len(inputs) < minSecurityQuestions || len(inputs) > maxSecurityQuestions {
		return nil, ErrSecurityQuestionCount
	}

	stored := make([]storedSecurityQuestion, 0, len(inputs))
	dtos := make([]SecurityQuestionDTO, 0, len(inputs))
	// Keyed by the normalized prompt, so "First pet?" and "first pet?" collide.
	// Two prompts that read alike are two chances at one fact, and a person facing
	// them cannot tell which box wants which answer.
	seen := make(map[string]struct{}, len(inputs))

	for i, in := range inputs {
		question, err := validator.SanitizeString(in.Question, 1, maxSecurityQuestionRunes)
		if err != nil {
			return nil, fmt.Errorf("%w: question %d must be 1-%d characters and contain no markup: %w",
				ErrSecurityQuestionInvalid, i+1, maxSecurityQuestionRunes, err)
		}

		key := normalizeSecurityAnswer(question)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("%w: question %d repeats an earlier question — each one has to ask something different",
				ErrSecurityQuestionInvalid, i+1)
		}
		seen[key] = struct{}{}

		// Counted on the normalized form, because that is what will be hashed: an
		// answer of three spaces normalizes to nothing and would otherwise pass a
		// length check on what was typed.
		answer := normalizeSecurityAnswer(in.Answer)
		if n := utf8.RuneCountInString(answer); n < minSecurityAnswerRunes || n > maxSecurityAnswerRunes {
			return nil, fmt.Errorf("%w: the answer to question %d must be %d-%d characters once leading, trailing and repeated spaces are ignored",
				ErrSecurityQuestionInvalid, i+1, minSecurityAnswerRunes, maxSecurityAnswerRunes)
		}

		hash, err := crypto.HashPasswordArgon2id(answer)
		if err != nil {
			return nil, fmt.Errorf("failed hashing security question answer: %w", err)
		}

		id := idgen.New("sq")
		stored = append(stored, storedSecurityQuestion{ID: id, Question: question, AnswerHash: hash})
		dtos = append(dtos, SecurityQuestionDTO{ID: id, Question: question})
	}

	client := s.repo.factory.GetClient(ctx, "", "")
	u, err := client.User.Get(ctx, userID)
	if err != nil {
		return nil, err
	}

	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	meta[securityQuestionsMetadataKey] = stored

	if err := client.User.UpdateOneID(userID).SetMetadata(meta).Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed saving security questions: %w", err)
	}

	return dtos, nil
}

// DeleteSecurityQuestions removes the account's roster, withdrawing the method.
//
// Removing the last recovery factor is not refused. Unlike a sign-in credential,
// a recovery factor is not what gets the owner in day to day, and an owner who
// decides the answers have become guessable has to be able to take them away —
// leaving them in place because nothing else is enrolled would keep the weakest
// method alive precisely when its owner has said not to trust it.
func (s *RecoveryService) DeleteSecurityQuestions(ctx context.Context, userID string) error {
	client := s.repo.factory.GetClient(ctx, "", "")
	u, err := client.User.Get(ctx, userID)
	if err != nil {
		return err
	}

	if u.Metadata == nil {
		return nil
	}
	if _, exists := u.Metadata[securityQuestionsMetadataKey]; !exists {
		return nil
	}

	meta := u.Metadata
	delete(meta, securityQuestionsMetadataKey)

	if err := client.User.UpdateOneID(userID).SetMetadata(meta).Exec(ctx); err != nil {
		return fmt.Errorf("failed removing security questions: %w", err)
	}
	return nil
}
