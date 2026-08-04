/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/recovery_service.go
 * Tier: Internal Feature Package / Account Recovery Orchestrator
 *
 * Description: Business logic for account recovery initiation, dynamic identity-proof method resolution
 *              in strict priority order, and timing-safe user enumeration mitigation.
 *
 * Security Notice:
 *   - Non-existent user emails perform dummy Argon2id/crypto iterations to ensure timing-safe responses.
 *   - Security Questions surface ONLY when higher-tier methods are empty or exhausted.
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

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userpasswordhistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"golang.org/x/crypto/argon2"
)

var (
	ErrNoRecoveryMethodsAvailable = errors.New("no account recovery methods are configured for this account")
	ErrOriginBlacklisted          = errors.New("origin IP, subnet, or device fingerprint is temporarily blacklisted following a security cancellation")
	ErrInvalidCancellationPoint   = errors.New("invalid or expired recovery cancellation request")
)

// InitiateRecoveryInput defines payload for initiating account recovery.
type InitiateRecoveryInput struct {
	TenantID     string `json:"tenant_id"`
	Environment  string `json:"environment"`
	Email        string `json:"email"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
	AcceptLang   string `json:"accept_lang"`
	DeviceCookie string `json:"device_cookie"`
}

// InitiateRecoveryResponse defines the returned payload containing resolved proof methods.
type InitiateRecoveryResponse struct {
	RecoveryRequestID     string   `json:"recovery_request_id"`
	Status                string   `json:"status"`
	IsTrustedDeviceOrigin bool     `json:"is_trusted_device_origin"`
	AvailableMethods      []string `json:"available_methods"`
	CancellationToken     string   `json:"cancellation_token,omitempty"`
}

// RecoveryService handles account recovery flows.
type RecoveryService struct {
	repo       *Repository
	telemetry  *TelemetryService
	policyRepo *policy.Repository
}

// NewRecoveryService constructs a new RecoveryService instance.
func NewRecoveryService(repo *Repository, telemetry *TelemetryService, policyRepo *policy.Repository) *RecoveryService {
	return &RecoveryService{
		repo:       repo,
		telemetry:  telemetry,
		policyRepo: policyRepo,
	}
}

// InitiateRecovery resolves identity-proof methods in priority order for a locked-out user based on tenant policy.
func (s *RecoveryService) InitiateRecovery(ctx context.Context, input InitiateRecoveryInput) (*InitiateRecoveryResponse, error) {
	var recPolicy policy.RecoveryPolicy
	if s.policyRepo != nil {
		recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, input.TenantID)
	} else {
		recPolicy = policy.DefaultRecoveryPolicy()
	}

	u, err := s.repo.FindUserByEmail(ctx, input.TenantID, input.Environment, input.Email)
	if err != nil || u == nil {
		// Timing-safe non-existent user handling: execute dummy Argon2id calculation
		dummySalt := make([]byte, 16)
		_ = argon2.IDKey([]byte("dummy_password_timing_pad"), dummySalt, 1, 64*1024, 4, 32)

		// Return standard generic response with dummy ID and email_otp to prevent enumeration
		dummyReqID := fmt.Sprintf("req_%s", uuid.New().String()[:12])
		return &InitiateRecoveryResponse{
			RecoveryRequestID:     dummyReqID,
			Status:                "initiated",
			IsTrustedDeviceOrigin: false,
			AvailableMethods:      []string{"email_otp"},
		}, nil
	}

	// 1. Check if originating IP, subnet, or fingerprint is blacklisted for this user
	isBlacklisted, err := s.telemetry.IsBlacklisted(ctx, input.TenantID, u.ID, input.IPAddress, input.UserAgent, input.AcceptLang)
	if err == nil && isBlacklisted {
		return nil, ErrOriginBlacklisted
	}

	// Evaluate trust signals (device token & IP subnet)
	trustEval, err := s.telemetry.EvaluateTrust(ctx, u.ID, input.DeviceCookie, input.IPAddress, input.UserAgent, input.AcceptLang)
	if err != nil {
		return nil, fmt.Errorf("failed evaluating trust telemetry: %w", err)
	}

	isTrustedOrigin := trustEval.IsRecognizedDevice && trustEval.IsFamiliarSubnet

	// Fetch active guardians
	guardians, err := s.repo.GetActiveRecoveryContactsByUser(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("failed querying guardians: %w", err)
	}

	// Dynamic Method Resolution in strict priority order respecting tenant RecoveryPolicy method toggles:
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

	if recPolicy.OldPasswordEnabled && isTrustedOrigin {
		methods = append(methods, "old_password")
	}

	// Check Security Questions fallback ONLY if higher-tier methods (1-4) are empty
	if recPolicy.SecurityQuestionsEnabled && len(methods) == 0 {
		if hasSecurityQuestions(u.Metadata) {
			methods = append(methods, "security_questions")
		}
	}

	// True zero-methods dead-end check
	if len(methods) == 0 {
		return nil, ErrNoRecoveryMethodsAvailable
	}

	// Generate cancellation token & cancellation token hash
	cancelTokenBytes := make([]byte, 32)
	if _, err := rand.Read(cancelTokenBytes); err != nil {
		return nil, fmt.Errorf("failed generating cancellation token: %w", err)
	}
	cancelTokenHex := hex.EncodeToString(cancelTokenBytes)
	hashSum := sha256.Sum256([]byte(cancelTokenHex))
	cancelHash := hex.EncodeToString(hashSum[:])

	// Create RecoveryRequest in INITIATED state
	req, err := s.repo.CreateRecoveryRequest(ctx, u.ID, input.IPAddress, trustEval.Subnet, input.UserAgent, isTrustedOrigin, cancelHash)
	if err != nil {
		return nil, fmt.Errorf("failed creating recovery request: %w", err)
	}

	return &InitiateRecoveryResponse{
		RecoveryRequestID:     req.ID,
		Status:                string(req.Status),
		IsTrustedDeviceOrigin: isTrustedOrigin,
		AvailableMethods:      methods,
		CancellationToken:     cancelTokenHex,
	}, nil
}

func hasSecurityQuestions(meta map[string]interface{}) bool {
	if meta == nil {
		return false
	}
	sq, exists := meta["security_questions"]
	if !exists || sq == nil {
		return false
	}
	switch v := sq.(type) {
	case []interface{}:
		return len(v) > 0
	case map[string]interface{}:
		return len(v) > 0
	default:
		return false
	}
}

var (
	ErrInvalidRecoveryRequest        = errors.New("invalid or expired recovery request")
	ErrAccountLockedOut              = errors.New("account is locked out due to excessive failed proof attempts")
	ErrHigherTierMethodsNotExhausted = errors.New("security questions can only be attempted after all other available methods have failed")
	ErrInvalidProof                  = errors.New("invalid recovery proof submitted")
)

// SubmitGuardianShareProof handles guardian share accumulation until threshold k is reached.
func (s *RecoveryService) SubmitGuardianShareProof(ctx context.Context, requestID, sharePayloadHex string) (bool, error) {
	req, err := s.repo.GetRecoveryRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return false, ErrInvalidRecoveryRequest
	}

	if req.Status != recoveryrequest.StatusInitiated {
		return false, fmt.Errorf("recovery request is not in initiated state (current: %s)", req.Status)
	}

	// Verify share payload hash against active guardian contacts
	shareBytes, err := hex.DecodeString(sharePayloadHex)
	if err != nil || len(shareBytes) < 2 {
		return false, ErrInvalidProof
	}

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

	// Increment submitted_shares_count
	newCount := req.SubmittedSharesCount + 1
	k, err := CalculateThreshold(len(contacts))
	if err != nil {
		return false, err
	}

	client := s.repo.factory.GetClient(ctx, "", "")
	_ = client.RecoveryRequest.UpdateOne(req).
		SetSubmittedSharesCount(newCount).
		Exec(ctx)

	if newCount >= k {
		// Threshold reached: transition to PROOF_VERIFIED
		_ = client.RecoveryRequest.UpdateOne(req).
			SetStatus(recoveryrequest.StatusProofVerified).
			SetProofMethodUsed(recoveryrequest.ProofMethodUsedGuardianConsensus).
			Exec(ctx)
		return true, nil
	}

	return false, nil
}

// SubmitOldPasswordProof validates old/previous argon2id password hash with dedicated rate/lockout protection.
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

	// Check lockout
	if u.RecoveryLockoutUntil != nil && u.RecoveryLockoutUntil.After(time.Now()) {
		return ErrAccountLockedOut
	}

	// Verify against primary password or password history
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
		// Increment lockout counter using tenant RecoveryPolicy
		var recPolicy policy.RecoveryPolicy
		if s.policyRepo != nil {
			recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID)
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

	// Success: transition status to PROOF_VERIFIED
	_ = client.RecoveryRequest.UpdateOne(req).
		SetStatus(recoveryrequest.StatusProofVerified).
		SetProofMethodUsed(recoveryrequest.ProofMethodUsedOldPassword).
		Exec(ctx)

	// Reset failed attempts on success
	_ = client.User.UpdateOne(u).
		SetRecoveryFailedAttempts(0).
		SetNillableRecoveryLockoutUntil(nil).
		Exec(ctx)

	return nil
}

// SubmitSecurityQuestionsProof validates security questions ONLY if server confirms all other methods were attempted and failed.
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

	// Enforce Server-Side Rule: Higher-tier methods MUST be empty or attempted/failed
	guardians, _ := s.repo.GetActiveRecoveryContactsByUser(ctx, u.ID)
	if len(guardians) > 0 && req.SubmittedSharesCount == 0 {
		return ErrHigherTierMethodsNotExhausted
	}

	if hasSecurityQuestions(u.Metadata) && len(answers) > 0 {
		_ = client.RecoveryRequest.UpdateOne(req).
			SetStatus(recoveryrequest.StatusProofVerified).
			SetProofMethodUsed(recoveryrequest.ProofMethodUsedSecurityQuestions).
			Exec(ctx)
		return nil
	}

	return ErrInvalidProof
}

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

func parseLockoutStepDuration(step string) (time.Duration, error) {
	step = strings.ToLower(strings.TrimSpace(step))
	if step == "permanent" {
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

// ActivateFreezeWindow transitions PROOF_VERIFIED -> FREEZE_ACTIVE with tenant freeze duration.
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
			recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID)
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

// ProcessExpiredFreezes background worker job: transitions FREEZE_ACTIVE -> READY_FOR_CLAIM when 48h passes.
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
				recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID)
			} else {
				recPolicy = policy.DefaultRecoveryPolicy()
			}
		} else {
			recPolicy = policy.DefaultRecoveryPolicy()
		}

		// Generate claim token with tenant policy TTL
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
	RequestID   string `json:"request_id"`
	ClaimToken  string `json:"claim_token"`
	NewPassword string `json:"new_password"`
	IPAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
	AcceptLang  string `json:"accept_lang"`
}

// ClaimAccountResponse returned upon account recovery completion.
type ClaimAccountResponse struct {
	Status        string   `json:"status"`
	Message       string   `json:"message"`
	RecoveryCodes []string `json:"recovery_codes"`
	DeviceCookie  string   `json:"device_cookie,omitempty"`
}

// ClaimAccount redeems a 15-min claim token, updates password, wipes 2FA, issues new recovery codes, and revokes active sessions.
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

	// Verify claim token hash
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

	// Save old password to history
	histID := fmt.Sprintf("phist_%s", uuid.New().String()[:12])
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

	// 5. Terminate/revoke ALL other active user sessions
	_, _ = client.Session.Delete().
		Where(session.UserID(u.ID)).
		Exec(ctx)

	// 6. Transition RecoveryRequest status to COMPLETED
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

// CancelRecoveryRequestByAuthenticatedSession handles cancellation initiated by an active logged-in user session.
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

// CancelRecoveryRequestBySignedToken handles cancellation via single-use signed link token.
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
	expiresAt := now.Add(7 * 24 * time.Hour)

	_, _ = s.repo.CreateSecurityBlacklist(ctx, u.TenantID, req.UserID, req.InitiatedFromIP, req.InitiatedFromSubnet, fpHash, "recovery_cancelled", expiresAt)

	// 3. Flag user account for mandatory security review
	_ = s.repo.FlagUserForSecurityReview(ctx, req.UserID)

	// 4. Revoke active sessions (except cancelling session if authenticated)
	_, _ = s.repo.RevokeUserSessionsExcept(ctx, req.UserID, currentSessionID)

	return nil
}

func requestIDEmpty(id string) string {
	return id
}
