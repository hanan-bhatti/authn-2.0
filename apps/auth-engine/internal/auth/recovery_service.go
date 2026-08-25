/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_service.go
 * Tier: Internal Feature Package / Account Recovery Orchestrator
 *
 * Description: Account recovery orchestration for locked-out users: initiation with tenant-policy-driven
 *              resolution of the available identity-proof methods, the guardian / old-password /
 *              security-question proof handlers, the freeze-window state machine through to account
 *              claim, and cancellation with origin blacklisting.
 *
 * Security Notice:
 *   - Every InitiateRecovery call takes at least recoveryInitiateFloor, so response latency does not
 *     reveal whether the supplied email resolves to an account.
 *   - Security questions are the weakest proof: they are offered only when no stronger method exists,
 *     and accepted only once the stronger methods have been attempted.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userpasswordhistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
)

var (
	// ErrNoRecoveryMethodsAvailable reports that the account exists but tenant policy plus the
	// account's own configuration leave it with no usable proof method. This is a dead end for
	// self-service recovery and needs operator intervention.
	ErrNoRecoveryMethodsAvailable = errors.New("no account recovery methods are configured for this account")

	// ErrOriginBlacklisted reports that the caller's IP, subnet, or device fingerprint is still
	// inside the blacklist window opened when a previous recovery attempt was cancelled.
	ErrOriginBlacklisted = errors.New("origin IP, subnet, or device fingerprint is temporarily blacklisted following a security cancellation")

	// ErrInvalidCancellationPoint reports that a cancellation cannot be applied: the token matched
	// nothing, or the request has already reached a terminal state. It is deliberately
	// undifferentiated so a caller cannot probe for live request IDs or tokens.
	ErrInvalidCancellationPoint = errors.New("invalid or expired recovery cancellation request")
)

// InitiateRecoveryInput defines payload for initiating account recovery.
type InitiateRecoveryInput struct {
	// TenantID selects the RecoveryPolicy that decides which proof methods are offered.
	TenantID string `json:"tenant_id"`
	// Environment scopes the email lookup, so the same address can exist per environment.
	Environment string `json:"environment"`
	// Email identifies the account. It may resolve to nothing; see InitiateRecovery.
	Email string `json:"email"`
	// IPAddress is the caller's address, used for blacklist matching and subnet familiarity.
	IPAddress string `json:"ip_address"`
	// UserAgent feeds the device fingerprint and is recorded on the request row.
	UserAgent string `json:"user_agent"`
	// AcceptLang is the second half of the device fingerprint input.
	AcceptLang string `json:"accept_lang"`
	// DeviceCookie is the signed trusted-device token, when the caller still holds one.
	DeviceCookie string `json:"device_cookie"`
}

// InitiateRecoveryResponse defines the returned payload containing resolved proof methods.
type InitiateRecoveryResponse struct {
	// RecoveryRequestID addresses the request in every subsequent proof and claim call.
	RecoveryRequestID string `json:"recovery_request_id"`
	// Status is the request's position in the state machine, "initiated" on this path.
	Status string `json:"status"`
	// IsTrustedDeviceOrigin reports whether both device and subnet were recognized. It gates the
	// old-password method and is persisted on the request.
	IsTrustedDeviceOrigin bool `json:"is_trusted_device_origin"`
	// AvailableMethods lists the permitted proof methods in descending trust order.
	AvailableMethods []string `json:"available_methods"`
	// SecurityQuestions carries the prompts to answer, and is present only when
	// "security_questions" is among AvailableMethods. It holds no answers and no
	// digests — only the prompt text and the ID each answer is keyed to.
	//
	// The prompts are the account holder's own words and could name a person or a
	// place, so they are sent only where that method is actually on offer, which is
	// only when nothing stronger exists. The miss path never offers it, so an absent
	// list says nothing about whether the address resolved.
	SecurityQuestions []SecurityQuestionDTO `json:"security_questions,omitempty"`
	// CancellationToken is the one-time secret delivered to the account owner so a legitimate owner
	// can kill an attacker-initiated recovery. Only its hash is stored, so this is the only
	// opportunity to read it.
	CancellationToken string `json:"cancellation_token,omitempty"`
}

// RecoveryService handles account recovery flows.
type RecoveryService struct {
	// repo provides user, recovery-request, and guardian persistence, plus the ent client used
	// directly for the updates that have no repository wrapper.
	repo *Repository
	// telemetry supplies device and subnet trust evaluation, and blacklist checks.
	telemetry *TelemetryService
	// policyRepo resolves the per-tenant RecoveryPolicy. When nil, defaults are used throughout.
	policyRepo *policy.Repository
}

// NewRecoveryService constructs a new RecoveryService instance. repo and telemetry are required;
// policyRepo may be nil, in which case every policy lookup falls back to
// policy.DefaultRecoveryPolicy.
func NewRecoveryService(repo *Repository, telemetry *TelemetryService, policyRepo *policy.Repository) *RecoveryService {
	return &RecoveryService{
		repo:       repo,
		telemetry:  telemetry,
		policyRepo: policyRepo,
	}
}

// recoveryInitiateFloor is the minimum wall-clock duration of an InitiateRecovery call.
//
// Account existence is otherwise observable through response latency: the hit and miss paths do
// different amounts of work, and an attacker who can time requests reads that difference even when
// the response bodies are identical. Holding every path to a common floor removes the differential
// rather than trying to balance the two paths against each other.
//
// The value sits above the service time of the slower path — the hit path, which additionally runs
// trust evaluation, the guardian read, and a request insert — with headroom for a loaded database.
// It is a compile-time constant rather than tenant configuration because it is a security bound,
// not a tuning knob: a floor an operator can lower beneath their own service time stops concealing
// anything. Recovery initiation is a rare, human-driven action, so the added latency is not
// meaningfully user-visible.
const recoveryInitiateFloor = 250 * time.Millisecond

// padToFloor blocks until at least floor has elapsed since start, and returns immediately if it
// already has. Callers defer it so that every return path pays the same cost, including early error
// returns — which are themselves account-existence signals.
func padToFloor(start time.Time, floor time.Duration) {
	if elapsed := time.Since(start); elapsed < floor {
		time.Sleep(floor - elapsed)
	}
}

// InitiateRecovery opens a recovery attempt for the account addressed by input.Email and returns the
// proof methods that account may use, in descending trust order, along with a single-use
// cancellation token whose SHA-256 hash is all the stored request retains.
//
// An email that resolves to no user still receives a well-formed "initiated" response carrying a
// synthetic request ID, so the miss path answers in the same shape as a hit; the deferred floor
// equalizes the latency of the two.
//
// It returns ErrOriginBlacklisted when the origin is inside a post-cancellation blacklist window,
// and ErrNoRecoveryMethodsAvailable when the account is real but has no usable proof method — that
// account cannot be recovered without an operator. A wrapped error means an infrastructure step
// failed (trust evaluation, the guardian read, entropy, or the request insert) and the attempt can
// be retried.
func (s *RecoveryService) InitiateRecovery(ctx context.Context, input InitiateRecoveryInput) (*InitiateRecoveryResponse, error) {
	// Deferred call arguments are evaluated here, so start is pinned to function entry.
	defer padToFloor(time.Now(), recoveryInitiateFloor)

	if p, ok := privacy.FromContext(ctx); !ok || p.TenantID == "" {
		ctx = privacy.NewContext(ctx, input.TenantID, "", input.Environment)
	}

	var recPolicy policy.RecoveryPolicy
	if s.policyRepo != nil {
		recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, input.TenantID, input.Environment)
	} else {
		recPolicy = policy.DefaultRecoveryPolicy()
	}

	sysCtx := privacy.NewBypassContext(ctx)
	u, err := s.repo.FindUserByEmail(sysCtx, input.TenantID, input.Environment, input.Email)
	if err != nil || u == nil {
		// Miss: answer in the shape of a hit. The deferred floor already covers the latency
		// difference, so this path does no compensating work — padding here with real
		// cryptographic work would only re-open a measurable gap in the other direction.
		dummyReqID := idgen.New("req")
		return &InitiateRecoveryResponse{
			RecoveryRequestID:     dummyReqID,
			Status:                "initiated",
			IsTrustedDeviceOrigin: false,
			AvailableMethods:      []string{"email_otp"},
		}, nil
	}

	// A telemetry failure does not block: only a positive match stops the flow.
	isBlacklisted, err := s.telemetry.IsBlacklisted(ctx, input.TenantID, input.Environment, u.ID, input.IPAddress, input.UserAgent, input.AcceptLang)
	if err == nil && isBlacklisted {
		return nil, ErrOriginBlacklisted
	}

	trustEval, err := s.telemetry.EvaluateTrust(ctx, u.ID, input.DeviceCookie, input.IPAddress, input.UserAgent, input.AcceptLang)
	if err != nil {
		return nil, fmt.Errorf("failed evaluating trust telemetry: %w", err)
	}

	// Both signals are required: a known device on a new network, or a new device on a known
	// network, is not a trusted origin.
	isTrustedOrigin := trustEval.IsRecognizedDevice && trustEval.IsFamiliarSubnet

	guardians, err := s.repo.GetActiveRecoveryContactsByUser(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("failed querying guardians: %w", err)
	}

	// Methods are appended strongest-first, and the slice order is the offer order. Each arm needs
	// both the tenant toggle and the account-side prerequisite.
	var methods []string

	if recPolicy.GuardiansEnabled && len(guardians) > 0 {
		methods = append(methods, "guardians")
	}

	if recPolicy.PhoneOTPEnabled && u.PhoneNumber != "" && u.PhoneVerified {
		methods = append(methods, "phone_otp")
	}

	if recPolicy.EmailOTPEnabled && u.Email != "" && u.EmailVerified {
		methods = append(methods, "email_otp")
	}

	// Knowledge of a former password proves little by itself, so it counts only from an origin the
	// account has used before.
	if recPolicy.OldPasswordEnabled && isTrustedOrigin {
		methods = append(methods, "old_password")
	}

	// Security questions are the weakest proof and are never offered alongside a stronger one.
	//
	// The prompts travel with the offer. Whoever is recovering the account has no session and no
	// other route to them, so a method offered without its questions is one they cannot attempt.
	var securityQuestions []SecurityQuestionDTO
	if recPolicy.SecurityQuestionsEnabled && len(methods) == 0 {
		// Decoded rather than merely probed for presence: a roster whose entries carry no answer
		// hash cannot be verified against, so offering it would advertise a method whose proof
		// always fails.
		enrolled, err := decodeSecurityQuestions(u.Metadata)
		if err == nil && len(enrolled) > 0 {
			methods = append(methods, "security_questions")
			securityQuestions = make([]SecurityQuestionDTO, len(enrolled))
			for i, q := range enrolled {
				securityQuestions[i] = SecurityQuestionDTO{ID: q.ID, Question: q.Question}
			}
		}
	}

	if len(methods) == 0 {
		return nil, ErrNoRecoveryMethodsAvailable
	}

	// The token goes to the account owner; only its digest is persisted, so a database reader can
	// neither cancel a recovery attempt nor forge the cancellation of one.
	cancelTokenBytes := make([]byte, 32)
	if _, err := rand.Read(cancelTokenBytes); err != nil {
		return nil, fmt.Errorf("failed generating cancellation token: %w", err)
	}
	cancelTokenHex := hex.EncodeToString(cancelTokenBytes)
	hashSum := sha256.Sum256([]byte(cancelTokenHex))
	cancelHash := hex.EncodeToString(hashSum[:])

	req, err := s.repo.CreateRecoveryRequest(ctx, u.ID, input.IPAddress, trustEval.Subnet, input.UserAgent, isTrustedOrigin, cancelHash)
	if err != nil {
		return nil, fmt.Errorf("failed creating recovery request: %w", err)
	}

	return &InitiateRecoveryResponse{
		RecoveryRequestID:     req.ID,
		Status:                string(req.Status),
		IsTrustedDeviceOrigin: isTrustedOrigin,
		AvailableMethods:      methods,
		SecurityQuestions:     securityQuestions,
		CancellationToken:     cancelTokenHex,
	}, nil
}

// cancelledRecoveryBlacklistWindow is how long the IP, subnet and device
// fingerprint that started a cancelled recovery stay blacklisted.
//
// Cancelling recovery means the account owner rejected an attempt they did not
// start, so the origin is treated as hostile: long enough to defeat a retry
// campaign, bounded so a shared or reassigned address is not blocked forever.
const cancelledRecoveryBlacklistWindow = 7 * 24 * time.Hour

var (
	// ErrInvalidRecoveryRequest reports that the request ID matched no row, or that the row is no
	// longer usable. It covers both cases so a caller cannot enumerate live request IDs.
	ErrInvalidRecoveryRequest = errors.New("invalid or expired recovery request")

	// ErrAccountLockedOut reports that the account is inside a recovery lockout window opened by
	// earlier failed old-password attempts. The window length comes from the tenant LockoutSchedule.
	ErrAccountLockedOut = errors.New("account is locked out due to excessive failed proof attempts")

	// ErrHigherTierMethodsNotExhausted reports a security-question submission that arrived before
	// the stronger methods were attempted, i.e. an attempt to jump straight to the weakest proof.
	ErrHigherTierMethodsNotExhausted = errors.New("security questions can only be attempted after all other available methods have failed")

	// ErrInvalidProof reports that the submitted proof did not verify. It is uniform across the
	// proof methods and reveals nothing about which part of the submission was wrong.
	ErrInvalidProof = errors.New("invalid recovery proof submitted")
)

// SubmitGuardianShareProof records one guardian's Shamir share against an initiated request and
// reports whether this submission completed the guardian consensus. sharePayloadHex is the
// hex-encoded raw share; it is matched by SHA-256 digest against the stored per-guardian hashes, so
// the server never holds a share itself. Reaching the threshold moves the request to
// PROOF_VERIFIED.
//
// A false return with a nil error means the share was accepted and the request is still short of the
// threshold. Errors: ErrInvalidRecoveryRequest for an unknown request; a plain error when the
// request has already left the initiated state; ErrInvalidProof when the payload is not hex, is
// shorter than a share can be, or matches no active guardian; and ErrInvalidGuardianCount when the
// active guardian count has drifted outside the 1..5 range the threshold rule covers.
func (s *RecoveryService) SubmitGuardianShareProof(ctx context.Context, requestID, sharePayloadHex string) (bool, error) {
	req, err := s.repo.GetRecoveryRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return false, ErrInvalidRecoveryRequest
	}

	if req.Status != recoveryrequest.StatusInitiated {
		return false, fmt.Errorf("recovery request is not in initiated state (current: %s)", req.Status)
	}

	shareBytes, err := hex.DecodeString(sharePayloadHex)
	if err != nil || len(shareBytes) < 2 {
		return false, ErrInvalidProof
	}

	// Guardian share hashes are digests of the raw share bytes, not of the hex text.
	hashSum := sha256.Sum256(shareBytes)
	shareHash := hex.EncodeToString(hashSum[:])

	contacts, err := s.repo.GetActiveRecoveryContactsByUser(ctx, req.UserID)
	if err != nil {
		return false, err
	}

	var matchedContact *ent.RecoveryContact
	for _, c := range contacts {
		if c.ShareHash == shareHash {
			matchedContact = c
			break
		}
	}

	if matchedContact == nil {
		return false, ErrInvalidProof
	}

	// The counter tracks accepted submissions, not distinct guardians.
	newCount := req.SubmittedSharesCount + 1
	// The threshold follows the guardian roster as it stands now, so revoking a guardian mid-flow
	// re-derives k from the smaller set.
	k, err := CalculateThreshold(len(contacts))
	if err != nil {
		return false, err
	}

	client := s.repo.factory.GetClient(ctx, "", "")
	_ = client.RecoveryRequest.UpdateOne(req).
		SetSubmittedSharesCount(newCount).
		Exec(ctx)

	if newCount >= k {
		_ = client.RecoveryRequest.UpdateOne(req).
			SetStatus(recoveryrequest.StatusProofVerified).
			SetProofMethodUsed(recoveryrequest.ProofMethodUsedGuardianConsensus).
			Exec(ctx)
		return true, nil
	}

	return false, nil
}

// SubmitOldPasswordProof verifies rawPassword against the account's current Argon2id hash and every
// retained history entry, and moves the request to PROOF_VERIFIED on a match, clearing the recovery
// failure counter. A former password is accepted as proof, which is why the method is confined to a
// trusted origin.
//
// Errors: ErrInvalidRecoveryRequest for an unknown request; a plain error when the request was not
// initiated from a trusted device and network; ErrAccountLockedOut while a lockout window is open;
// ErrInvalidProof when nothing matched, in which case the failure counter has been incremented and
// may have opened a new lockout window per the tenant schedule; and a repository error when the
// user or history read fails.
func (s *RecoveryService) SubmitOldPasswordProof(ctx context.Context, requestID, rawPassword string) error {
	req, err := s.repo.GetRecoveryRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return ErrInvalidRecoveryRequest
	}

	if !req.IsTrustedDeviceOrigin {
		return errors.New("old password proof is disallowed from unfamiliar device or network")
	}

	client := s.repo.factory.GetClient(ctx, "", "")
	u, err := client.User.Get(ctx, req.UserID)
	if err != nil {
		return err
	}

	// The lockout is checked before any hashing, so a locked account costs an attacker nothing to
	// probe and yields no verification signal.
	if u.RecoveryLockoutUntil != nil && u.RecoveryLockoutUntil.After(time.Now()) {
		return ErrAccountLockedOut
	}

	history, err := client.UserPasswordHistory.Query().
		Where(userpasswordhistory.UserID(req.UserID)).
		All(ctx)
	if err != nil {
		return err
	}

	var matchFound bool
	if crypto.VerifyPasswordArgon2id(rawPassword, u.PasswordHash) {
		matchFound = true
	} else {
		for _, h := range history {
			if crypto.VerifyPasswordArgon2id(rawPassword, h.PasswordHash) {
				matchFound = true
				break
			}
		}
	}

	if !matchFound {
		var recPolicy policy.RecoveryPolicy
		if s.policyRepo != nil {
			recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID, string(u.Environment))
		} else {
			recPolicy = policy.DefaultRecoveryPolicy()
		}

		attempts := u.RecoveryFailedAttempts + 1
		lockoutUntil := calculateLockoutTimeWithPolicy(attempts, recPolicy)

		_ = client.User.UpdateOne(u).
			SetRecoveryFailedAttempts(attempts).
			SetNillableRecoveryLockoutUntil(lockoutUntil).
			Exec(ctx)

		return ErrInvalidProof
	}

	_ = client.RecoveryRequest.UpdateOne(req).
		SetStatus(recoveryrequest.StatusProofVerified).
		SetProofMethodUsed(recoveryrequest.ProofMethodUsedOldPassword).
		Exec(ctx)

	// A successful proof clears the counter, so an owner who fumbled earlier attempts is not left
	// carrying escalated lockout steps into the next flow.
	_ = client.User.UpdateOne(u).
		SetRecoveryFailedAttempts(0).
		SetNillableRecoveryLockoutUntil(nil).
		Exec(ctx)

	return nil
}

// SubmitSecurityQuestionsProof applies the last-resort proof and, on success, moves the request to
// PROOF_VERIFIED. The ordering rule is enforced server-side: an account with active guardians must
// have at least one share submitted before its questions may be used, so a caller cannot bypass the
// stronger method by simply not attempting it.
//
// Every enrolled question must be answered, and every answer must match its stored Argon2id digest
// after normalization. All-or-nothing rather than a threshold: the answers are low-entropy and
// correlated — someone who knows a birthplace often knows a mother's maiden name — so accepting a
// subset would cost an attacker far less than the fraction suggests. Answers are keyed by question
// ID, and every question is looked up in the submission rather than iterating the submission, so
// extra keys are ignored and a missing one fails.
//
// A failed attempt increments the account's recovery failure counter and can open a lockout window
// under the tenant schedule, on the same terms as a failed old-password proof. Without that these
// answers would be an unlimited guessing oracle, which for a fact like a birthplace is a short list.
//
// Errors: ErrInvalidRecoveryRequest for an unknown request; ErrHigherTierMethodsNotExhausted when
// guardians exist and none has submitted; ErrAccountLockedOut while a lockout window is open;
// ErrInvalidProof when the account has no questions enrolled, when an answer is missing, or when one
// does not match; and a repository error when the user read fails.
func (s *RecoveryService) SubmitSecurityQuestionsProof(ctx context.Context, requestID string, answers map[string]string) error {
	req, err := s.repo.GetRecoveryRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return ErrInvalidRecoveryRequest
	}

	client := s.repo.factory.GetClient(ctx, "", "")
	u, err := client.User.Get(ctx, req.UserID)
	if err != nil {
		return err
	}

	guardians, _ := s.repo.GetActiveRecoveryContactsByUser(ctx, u.ID)
	if len(guardians) > 0 && req.SubmittedSharesCount == 0 {
		return ErrHigherTierMethodsNotExhausted
	}

	// Checked before any hashing, so a locked account costs an attacker nothing to probe and yields
	// no verification signal.
	if u.RecoveryLockoutUntil != nil && u.RecoveryLockoutUntil.After(time.Now()) {
		return ErrAccountLockedOut
	}

	stored, err := decodeSecurityQuestions(u.Metadata)
	if err != nil {
		return err
	}
	if len(stored) == 0 {
		return ErrInvalidProof
	}

	// Every answer is checked even once one has failed, rather than returning on the first mismatch.
	// Returning early would make the response time report how many leading answers were right, which
	// turns one submission into a per-question oracle and defeats the all-or-nothing rule.
	allMatched := true
	for _, q := range stored {
		submitted, provided := answers[q.ID]
		if !provided {
			allMatched = false
			// Verified against a hash that matches nothing, so a missing answer costs the same
			// Argon2id computation as a wrong one and the two are not distinguishable by timing.
			crypto.VerifyPasswordArgon2id("", crypto.DummyArgon2idHash)
			continue
		}
		if !crypto.VerifyPasswordArgon2id(normalizeSecurityAnswer(submitted), q.AnswerHash) {
			allMatched = false
		}
	}

	if !allMatched {
		var recPolicy policy.RecoveryPolicy
		if s.policyRepo != nil {
			recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID, string(u.Environment))
		} else {
			recPolicy = policy.DefaultRecoveryPolicy()
		}

		attempts := u.RecoveryFailedAttempts + 1
		lockoutUntil := calculateLockoutTimeWithPolicy(attempts, recPolicy)

		_ = client.User.UpdateOne(u).
			SetRecoveryFailedAttempts(attempts).
			SetNillableRecoveryLockoutUntil(lockoutUntil).
			Exec(ctx)

		return ErrInvalidProof
	}

	_ = client.RecoveryRequest.UpdateOne(req).
		SetStatus(recoveryrequest.StatusProofVerified).
		SetProofMethodUsed(recoveryrequest.ProofMethodUsedSecurityQuestions).
		Exec(ctx)

	// A successful proof clears the counter, so an owner who mistyped earlier is not left carrying
	// escalated lockout steps into the next flow.
	_ = client.User.UpdateOne(u).
		SetRecoveryFailedAttempts(0).
		SetNillableRecoveryLockoutUntil(nil).
		Exec(ctx)

	return nil
}

// calculateLockoutTimeWithPolicy maps a cumulative failed-attempt count onto the tenant lockout
// schedule and returns the instant the lockout ends, or nil when no lockout applies. The first
// three failures are free, so attempt 4 takes schedule step 0, attempt 5 step 1, and so on; once
// attempts run past the end of the schedule the final step repeats indefinitely. An empty schedule
// disables lockout entirely, and a step the parser rejects degrades to 24 hours rather than to no
// lockout at all.
func calculateLockoutTimeWithPolicy(attempts int, recPolicy policy.RecoveryPolicy) *time.Time {
	if attempts <= 3 || len(recPolicy.LockoutSchedule) == 0 {
		return nil
	}

	idx := attempts - 4
	if idx >= len(recPolicy.LockoutSchedule) {
		idx = len(recPolicy.LockoutSchedule) - 1
	}

	stepStr := recPolicy.LockoutSchedule[idx]
	dur, err := parseLockoutStepDuration(stepStr)
	if err != nil {
		dur = 24 * time.Hour
	}

	t := time.Now().Add(dur)
	return &t
}

// parseLockoutStepDuration parses one lockout schedule step, case-insensitively and ignoring
// surrounding space. It accepts "permanent", the week and day suffixes ("2w", "30d") that
// time.ParseDuration does not understand, and otherwise any Go duration string. It returns an error
// for a malformed step or a non-positive one; a zero or negative lockout would be a silent bypass,
// so it is rejected rather than clamped.
func parseLockoutStepDuration(step string) (time.Duration, error) {
	step = strings.ToLower(strings.TrimSpace(step))
	if step == "permanent" {
		// The maximum time.Duration, roughly 292 years out — effectively never expiring.
		return time.Duration(1<<63 - 1), nil
	}
	if strings.HasSuffix(step, "w") {
		weeks, err := strconv.Atoi(strings.TrimSuffix(step, "w"))
		if err != nil || weeks <= 0 {
			return 0, fmt.Errorf("invalid week step: %s", step)
		}
		return time.Duration(weeks) * 7 * 24 * time.Hour, nil
	}
	if strings.HasSuffix(step, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(step, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day step: %s", step)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	dur, err := time.ParseDuration(step)
	if err != nil || dur <= 0 {
		return 0, fmt.Errorf("invalid duration step: %s", step)
	}
	return dur, nil
}

// ActivateFreezeWindow moves a PROOF_VERIFIED request to FREEZE_ACTIVE and returns the updated row.
// The freeze is the notification window: proof has succeeded, but the account is not handed over
// until the tenant's FreezeWindowHours elapse, giving the real owner time to cancel.
//
// Errors: ErrInvalidRecoveryRequest for an unknown request; a plain error when the request is in
// any status other than PROOF_VERIFIED, which makes the transition idempotent-safe against repeat
// calls; and a wrapped error when the update fails. A failed user or policy read is not fatal —
// the default policy applies.
func (s *RecoveryService) ActivateFreezeWindow(ctx context.Context, requestID string) (*ent.RecoveryRequest, error) {
	req, err := s.repo.GetRecoveryRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return nil, ErrInvalidRecoveryRequest
	}

	if req.Status != recoveryrequest.StatusProofVerified {
		return nil, fmt.Errorf("cannot activate freeze window for request in status %s", req.Status)
	}

	var recPolicy policy.RecoveryPolicy
	if s.policyRepo != nil {
		if u, err := s.repo.GetUserByID(ctx, req.UserID); err == nil && u != nil {
			recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID, string(u.Environment))
		} else {
			recPolicy = policy.DefaultRecoveryPolicy()
		}
	} else {
		recPolicy = policy.DefaultRecoveryPolicy()
	}

	now := time.Now()
	freezeExpiresAt := now.Add(time.Duration(recPolicy.FreezeWindowHours) * time.Hour)

	client := s.repo.factory.GetClient(ctx, "", "")
	updated, err := client.RecoveryRequest.UpdateOne(req).
		SetStatus(recoveryrequest.StatusFreezeActive).
		SetFreezeStartedAt(now).
		SetFreezeExpiresAt(freezeExpiresAt).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed setting freeze_active status: %w", err)
	}

	return updated, nil
}

// ProcessExpiredFreezes is the background sweep that moves every FREEZE_ACTIVE request whose window
// has elapsed to READY_FOR_CLAIM, minting a claim token per request and storing only its SHA-256
// hash. It returns the number of requests transitioned.
//
// A request that fails mid-sweep — no entropy, or a rejected update — is skipped and left in
// FREEZE_ACTIVE for the next run, so the count can be lower than the number of expired requests
// without that being an error. An error return means the query for expired requests itself failed
// and nothing was processed.
//
// The claim token is not returned: the caller learns it through the out-of-band notification, which
// is what makes the claim step require access to a channel the owner controls.
func (s *RecoveryService) ProcessExpiredFreezes(ctx context.Context) (int, error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	now := time.Now()

	expiredRequests, err := client.RecoveryRequest.Query().
		Where(
			recoveryrequest.StatusEQ(recoveryrequest.StatusFreezeActive),
			recoveryrequest.FreezeExpiresAtLTE(now),
		).
		All(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed querying expired freeze requests: %w", err)
	}

	processedCount := 0
	for _, req := range expiredRequests {
		var recPolicy policy.RecoveryPolicy
		if s.policyRepo != nil {
			if u, err := s.repo.GetUserByID(ctx, req.UserID); err == nil && u != nil {
				recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID, string(u.Environment))
			} else {
				recPolicy = policy.DefaultRecoveryPolicy()
			}
		} else {
			recPolicy = policy.DefaultRecoveryPolicy()
		}

		claimTokenBytes := make([]byte, 32)
		if _, err := rand.Read(claimTokenBytes); err != nil {
			continue
		}
		claimTokenHex := hex.EncodeToString(claimTokenBytes)
		claimHashSum := sha256.Sum256([]byte(claimTokenHex))
		claimHash := hex.EncodeToString(claimHashSum[:])
		claimExpiresAt := now.Add(time.Duration(recPolicy.ClaimTokenTTLMinutes) * time.Minute)

		err = client.RecoveryRequest.UpdateOne(req).
			SetStatus(recoveryrequest.StatusReadyForClaim).
			SetClaimTokenHash(claimHash).
			SetClaimTokenExpiresAt(claimExpiresAt).
			Exec(ctx)
		if err == nil {
			processedCount++
		}
	}

	return processedCount, nil
}

// ClaimAccountInput payload for redeeming claim token and resetting account credentials.
type ClaimAccountInput struct {
	// RequestID addresses the READY_FOR_CLAIM request being redeemed.
	RequestID string `json:"request_id"`
	// ClaimToken is the raw token from the out-of-band notification, checked against the stored hash.
	ClaimToken string `json:"claim_token"`
	// NewPassword replaces the account password; the previous hash moves to history.
	NewPassword string `json:"new_password"`
	// IPAddress, UserAgent, and AcceptLang describe the claiming client and are used to register it
	// as a trusted device, so the recovered account has one known origin to return from.
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	AcceptLang string `json:"accept_lang"`
}

// ClaimAccountResponse returned upon account recovery completion.
type ClaimAccountResponse struct {
	// Status is the terminal outcome, "completed".
	Status string `json:"status"`
	// Message is human-readable text describing what the claim changed.
	Message string `json:"message"`
	// RecoveryCodes is the freshly minted code set, shown once because 2FA was cleared and the
	// account otherwise has no second factor left.
	RecoveryCodes []string `json:"recovery_codes"`
	// DeviceCookie is the signed trusted-device token for the claiming client, empty when device
	// registration did not produce one.
	DeviceCookie string `json:"device_cookie,omitempty"`
}

// ClaimAccount redeems a claim token and completes recovery: it sets the new password after moving
// the old hash to history, clears every enrolled 2FA method, mints a fresh recovery code set,
// registers the claiming client as a trusted device, deletes all of the account's sessions, and
// marks the request COMPLETED.
//
// Clearing 2FA is what makes recovery work for a user who lost their second factor, and is also why
// every session is dropped: an attacker who had a live session must not keep it across a credential
// reset. The token is compared as a SHA-256 digest, so the stored row never holds the token itself.
//
// Errors: ErrInvalidRecoveryRequest for an unknown request; a plain error when the request is not
// in READY_FOR_CLAIM, when the token has expired, or when the token does not match; and a wrapped
// error when hashing the new password fails or the user read fails. Once past those checks the
// mutations proceed best-effort and are not rolled back.
func (s *RecoveryService) ClaimAccount(ctx context.Context, input ClaimAccountInput) (*ClaimAccountResponse, error) {
	req, err := s.repo.GetRecoveryRequestByID(ctx, requestIDEmpty(input.RequestID))
	if err != nil || req == nil {
		return nil, ErrInvalidRecoveryRequest
	}

	if req.Status != recoveryrequest.StatusReadyForClaim {
		return nil, fmt.Errorf("recovery request is not in ready_for_claim state (current: %s)", req.Status)
	}

	if req.ClaimTokenExpiresAt != nil && req.ClaimTokenExpiresAt.Before(time.Now()) {
		return nil, errors.New("claim token has expired")
	}

	claimHashSum := sha256.Sum256([]byte(input.ClaimToken))
	claimHash := hex.EncodeToString(claimHashSum[:])
	if req.ClaimTokenHash == nil || *req.ClaimTokenHash != claimHash {
		return nil, errors.New("invalid claim token")
	}

	client := s.repo.factory.GetClient(ctx, "", "")
	u, err := client.User.Get(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	// 1. Update Password Hash with Argon2id & record in UserPasswordHistory
	newPassHash, err := crypto.HashPasswordArgon2id(input.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed hashing new password: %w", err)
	}

	// The outgoing hash is archived before the update overwrites it, which is what keeps it usable
	// as old-password proof in a later recovery.
	histID := idgen.New("phist")
	_ = client.UserPasswordHistory.Create().
		SetID(histID).
		SetUserID(u.ID).
		SetPasswordHash(u.PasswordHash).
		Exec(ctx)

	_ = client.User.UpdateOne(u).
		SetPasswordHash(newPassHash).
		SetRecoveryFailedAttempts(0).
		SetNillableRecoveryLockoutUntil(nil).
		Exec(ctx)

	// 2. Clear ALL 2FA methods
	_, _ = client.TwoFactorMethod.Delete().
		Where(twofactormethod.UserID(u.ID)).
		Exec(ctx)

	// 3. Issue fresh set of recovery codes
	codes := make([]string, 8)
	for i := 0; i < 8; i++ {
		b := make([]byte, 5)
		_, _ = rand.Read(b)
		codes[i] = fmt.Sprintf("%X-%X", b[:2], b[2:])
	}

	// 4. Register current device as trusted device
	deviceCookie, _ := s.telemetry.RecordSuccessfulLoginTelemetry(ctx, u.ID, "", input.IPAddress, input.UserAgent, input.AcceptLang)

	// 5. Every session is dropped, including any the attacker holds. Trusted-device registration
	// above issues a cookie rather than a session, so it survives this delete.
	_, _ = client.Session.Delete().
		Where(session.UserID(u.ID)).
		Exec(ctx)

	// 6. The terminal status is what prevents the claim token from being redeemed twice.
	_ = client.RecoveryRequest.UpdateOne(req).
		SetStatus(recoveryrequest.StatusCompleted).
		SetCompletedAt(time.Now()).
		Exec(ctx)

	return &ClaimAccountResponse{
		Status:        "completed",
		Message:       "Account successfully recovered. All prior sessions revoked and 2FA reset.",
		RecoveryCodes: codes,
		DeviceCookie:  deviceCookie,
	}, nil
}

// CancelRecoveryRequestByAuthenticatedSession cancels a recovery attempt on behalf of a user who is
// already logged in — the strongest possible denial that the attempt is legitimate. currentSessionID
// is spared when sessions are revoked, so the cancelling user is not logged out by their own action.
//
// It returns ErrInvalidRecoveryRequest when the request is unknown or belongs to a different user,
// keeping the two indistinguishable so one user cannot probe another's request IDs, and
// ErrInvalidCancellationPoint when the request has already completed, cancelled, or expired.
func (s *RecoveryService) CancelRecoveryRequestByAuthenticatedSession(ctx context.Context, userID, requestID, currentSessionID string) error {
	req, err := s.repo.GetRecoveryRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return ErrInvalidRecoveryRequest
	}

	if req.UserID != userID {
		return ErrInvalidRecoveryRequest
	}

	if req.Status == recoveryrequest.StatusCompleted || req.Status == recoveryrequest.StatusCancelled || req.Status == recoveryrequest.StatusExpired {
		return ErrInvalidCancellationPoint
	}

	return s.executeCancellation(ctx, req, currentSessionID)
}

// CancelRecoveryRequestBySignedToken cancels a recovery attempt for a locked-out owner who cannot
// log in, using the token issued at initiation. The request is found by the token's SHA-256 digest,
// so possession of the token is the entire authorization: holding it is proof of access to the
// account's notification channel. Every session is revoked, since no session can be trusted here.
//
// It returns ErrInvalidCancellationPoint for a blank token, a token matching no request, or a
// request already in a terminal state — the last of which is also what makes the token single-use,
// as a replay finds the request cancelled.
func (s *RecoveryService) CancelRecoveryRequestBySignedToken(ctx context.Context, rawToken string) error {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return ErrInvalidCancellationPoint
	}

	hashSum := sha256.Sum256([]byte(rawToken))
	cancelHash := hex.EncodeToString(hashSum[:])

	req, err := s.repo.GetRecoveryRequestByCancellationHash(ctx, cancelHash)
	if err != nil || req == nil {
		return ErrInvalidCancellationPoint
	}

	if req.Status == recoveryrequest.StatusCompleted || req.Status == recoveryrequest.StatusCancelled || req.Status == recoveryrequest.StatusExpired {
		return ErrInvalidCancellationPoint
	}

	return s.executeCancellation(ctx, req, "")
}

// executeCancellation applies the cancellation itself: it marks the request CANCELLED, blacklists
// the origin the attempt came from for seven days, flags the account for security review, and
// revokes the account's sessions apart from currentSessionID. An empty currentSessionID revokes all
// of them.
//
// A cancellation means someone tried to take the account, so the origin is treated as hostile
// rather than merely turned away. It returns a wrapped error when the status update or the user
// read fails; the hardening steps after those are best-effort, because the cancellation is already
// durable once the status is committed and a partial failure must not leave the request live.
func (s *RecoveryService) executeCancellation(ctx context.Context, req *ent.RecoveryRequest, currentSessionID string) error {
	now := time.Now()
	client := s.repo.factory.GetClient(ctx, "", "")

	// 1. Transition RecoveryRequest status to CANCELLED
	err := client.RecoveryRequest.UpdateOne(req).
		SetStatus(recoveryrequest.StatusCancelled).
		SetCancelledAt(now).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed updating recovery request status to cancelled: %w", err)
	}

	// Fetch user to get TenantID
	u, err := s.repo.GetUserByID(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("failed fetching user for cancellation: %w", err)
	}

	// 2. Blacklist originating IP, subnet, and device fingerprint for 7 days
	fpHash := ComputeFingerprintHash(req.InitiatedFromUserAgent, "")
	expiresAt := now.Add(cancelledRecoveryBlacklistWindow)

	_, _ = s.repo.CreateSecurityBlacklist(ctx, u.TenantID, req.UserID, req.InitiatedFromIP, req.InitiatedFromSubnet, fpHash, "recovery_cancelled", expiresAt)

	// 3. Flag user account for mandatory security review
	_ = s.repo.FlagUserForSecurityReview(ctx, req.UserID)

	// 4. Revoke active sessions (except cancelling session if authenticated)
	_, _ = s.repo.RevokeUserSessionsExcept(ctx, req.UserID, currentSessionID)

	return nil
}

// requestIDEmpty returns id unchanged. It is a pass-through at the ClaimAccount call site and
// applies no normalization or validation.
func requestIDEmpty(id string) string {
	return id
}
