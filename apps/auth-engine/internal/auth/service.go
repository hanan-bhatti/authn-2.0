/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/service.go
 * Tier: Internal Feature Package / Auth Service
 *
 * Description: Core authentication domain logic handling signup, login, session issuance,
 *              API key validation, and password security.
 *
 * Security Notice:
 *   - Passwords must be hashed using Argon2id (t=3, m=64MB, p=4).
 *   - Refresh tokens are stored strictly as SHA-256 hashes.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	emailPkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	smsPkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidCredentials        = errors.New("invalid email or password")
	ErrUserAlreadyExists         = errors.New("user with this email already exists")
	ErrInvalidApiKey             = errors.New("invalid or expired api key")
	ErrInvalidToken              = errors.New("invalid or revoked token")
	ErrEmailVerificationRequired = errors.New("email verification required before signing in")
	Err2FARequired               = errors.New("2FA verification required before signing in")
	ErrNoPendingTOTP             = errors.New("no pending TOTP enrollment found")
	ErrInvalidTOTPCode           = errors.New("invalid 6-digit TOTP code")
	ErrInvalidRecoveryCode       = errors.New("invalid recovery code")
	ErrRecoveryCodeAlreadyUsed   = errors.New("this recovery code has already been used")
	ErrPasskeyCloneDetected      = errors.New("authenticator signature counter regression detected: potential cloned or replayed authenticator")
	ErrPasskeyNotFound          = errors.New("passkey not found or does not belong to user")
	ErrAmbiguous2FAMethod        = errors.New("multiple 2FA methods enabled; 'method' field is required to specify which 2FA method to verify")
	ErrSMSOTPExpired             = errors.New("SMS OTP verification code has expired or is invalid")
	ErrTooManySMSRequests        = errors.New("too many OTP requests; please wait before requesting another code")
)

type SMSOTPState struct {
	PhoneNumber string
	Code        string
	ExpiresAt   time.Time
}

type smsRateLimitEntry struct {
	Count     int
	WindowEnd time.Time
}

// TOTPEnrollResult contains secret and URI returned on 2FA enrollment.
type TOTPEnrollResult struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// ConfirmTOTPResult contains confirmation message and optional auto-generated backup recovery codes.
type ConfirmTOTPResult struct {
	Message              string   `json:"message"`
	RecoveryCodes        []string `json:"recovery_codes,omitempty"`
	RecoveryCodesCreated bool     `json:"recovery_codes_created"`
}

// RecoveryCodesStatusResult contains remaining count of unused recovery codes.
type RecoveryCodesStatusResult struct {
	RemainingCount   int  `json:"remaining_count"`
	TotalCount       int  `json:"total_count"`
	HasRecoveryCodes bool `json:"has_recovery_codes"`
}

// PasskeyDTO contains public details of a registered WebAuthn passkey.
type PasskeyDTO struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	CredentialID string                 `json:"credential_id"`
	SignCount    uint32                 `json:"sign_count"`
	CreatedAt    string                 `json:"created_at"`
	LastUsedAt   *string                `json:"last_used_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// WebAuthnUserAdapter implements the webauthn.User interface for an ent.User and its credentials.
type WebAuthnUserAdapter struct {
	User        *ent.User
	Credentials []webauthn.Credential
}

func (u *WebAuthnUserAdapter) WebAuthnID() []byte {
	return []byte(u.User.ID)
}

func (u *WebAuthnUserAdapter) WebAuthnName() string {
	return u.User.Email
}

func (u *WebAuthnUserAdapter) WebAuthnDisplayName() string {
	if u.User.Name != "" {
		return u.User.Name
	}
	return u.User.Email
}

func (u *WebAuthnUserAdapter) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUserAdapter) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// Service handles domain business logic for authentication.
type Service struct {
	repo             *Repository
	config           *config.EnvConfig
	emailProvider    emailPkg.EmailProvider
	smsProvider      smsPkg.SMSProvider
	webauthn         *webauthn.WebAuthn
	webauthnSessions sync.Map
	pendingSMSOTPs   sync.Map
	smsRateLimits    sync.Map
}

// NewService creates a new authentication domain service instance.
func NewService(repo *Repository, cfg *config.EnvConfig, emailProvider emailPkg.EmailProvider, smsProviders ...smsPkg.SMSProvider) *Service {
	if emailProvider == nil {
		emailProvider = emailPkg.NewNoopProvider()
	}
	var smsProv smsPkg.SMSProvider
	if len(smsProviders) > 0 && smsProviders[0] != nil {
		smsProv = smsProviders[0]
	} else if cfg != nil {
		var err error
		smsProv, err = smsPkg.NewSMSProvider(cfg)
		if err != nil {
			log.Printf("⚠️ SMS Provider warning: %v. Falling back to NoopProvider.", err)
			smsProv = smsPkg.NewNoopProvider()
		}
	} else {
		smsProv = smsPkg.NewNoopProvider()
	}
	var web *webauthn.WebAuthn
	if cfg != nil && cfg.WebAuthnRPID != "" {
		wconfig := &webauthn.Config{
			RPDisplayName: cfg.WebAuthnRPDisplayName,
			RPID:          cfg.WebAuthnRPID,
			RPOrigins:     cfg.WebAuthnRPOrigins,
		}
		var err error
		web, err = webauthn.New(wconfig)
		if err != nil {
			log.Printf("⚠️ Warning: Failed initializing WebAuthn instance: %v", err)
		}
	}
	return &Service{
		repo:          repo,
		config:        cfg,
		emailProvider: emailProvider,
		smsProvider:   smsProv,
		webauthn:      web,
	}
}

// ValidateApiKey checks a publishable (pk_...) or secret (sk_...) API key against database hashes.
//
// Parameters:
//   - ctx: Request context.
//   - rawKey: Raw API key header string.
//
// Returns:
//   - *ent.ApiKey: Validated API key entity.
//   - error: ErrInvalidApiKey if key is invalid or revoked.
func (s *Service) ValidateApiKey(ctx context.Context, rawKey string) (*ent.ApiKey, error) {
	if rawKey == "" {
		return nil, ErrInvalidApiKey
	}

	h := hmac.New(sha256.New, []byte(s.config.AuthnAPIKeyPepper))
	h.Write([]byte(rawKey))
	keyHash := hex.EncodeToString(h.Sum(nil))

	key, err := s.repo.FindApiKeyByHash(ctx, keyHash)
	if err != nil || key == nil {
		return nil, ErrInvalidApiKey
	}

	if key.RevokedAt != nil {
		return nil, ErrInvalidApiKey
	}
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, ErrInvalidApiKey
	}

	return key, nil
}

// SignUpWithPassword registers a new user with password credentials.
//
// Parameters:
//   - ctx: Request context.
//   - tenantID: Tenant ID scope.
//   - env: Environment mode ("test" or "live").
//   - email: User registered email address.
//   - password: Plain text password string.
//   - name: Optional full name string.
//
// Returns:
//   - *ent.User: Created user entity.
//   - string: Raw 64-byte opaque refresh token string.
//   - error: ErrUserAlreadyExists or creation error.
func (s *Service) SignUpWithPassword(ctx context.Context, tenantID string, env string, email string, password string, name string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	if err := s.repo.EnsureTenantExists(ctx, tenantID); err != nil {
		return nil, "", "", err
	}

	existing, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)
	if err != nil {
		return nil, "", "", err
	}
	if existing != nil {
		return nil, "", "", ErrUserAlreadyExists
	}

	passwordHash, err := crypto.HashPasswordArgon2id(password)
	if err != nil {
		return nil, "", "", err
	}

	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	u, err := s.repo.CreateUser(ctx, userID, tenantID, env, email, passwordHash, name)
	if err != nil {
		return nil, "", "", err
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", "", fmt.Errorf("failed generating refresh token: %w", err)
	}
	rawRefreshToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_, err = s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt)
	if err != nil {
		return nil, "", "", err
	}

	// Issue 15-minute JWT Access Token
	accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	// Audit Log recording
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, tenantID, u.ID, "user.signed_up", ipAddress, userAgent, "")

	// Send Email Verification (Non-blocking log on delivery error)
	if err := s.SendVerificationEmail(ctx, u); err != nil {
		log.Printf("[AuthService] Warning: Failed sending verification email to %s: %v", u.Email, err)
	}

	return u, accessToken, rawRefreshToken, nil
}

// SendVerificationEmail generates a 32-byte token and sends the verification email.
func (s *Service) SendVerificationEmail(ctx context.Context, u *ent.User) error {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed generating verification token: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	expiresAt := time.Now().Add(24 * time.Hour)
	if err := s.repo.SetUserEmailVerificationToken(ctx, u.ID, tokenHash, expiresAt); err != nil {
		return err
	}

	verifyURL := fmt.Sprintf("%s/v1/client/verify-email?token=%s", s.config.AppBaseURL, rawToken)

	htmlBody, textBody, err := emailPkg.RenderVerificationEmail(emailPkg.VerificationEmailData{
		UserName:         u.Name,
		VerificationLink: verifyURL,
		AppName:          "Authn Platform",
		ExpiresInHours:   24,
	})
	if err != nil {
		return fmt.Errorf("failed rendering email template: %w", err)
	}

	return s.emailProvider.Send(ctx, u.Email, "Verify your email address", htmlBody, textBody)
}

// VerifyEmailToken validates the single-use token and sets email_verified = true.
func (s *Service) VerifyEmailToken(ctx context.Context, rawToken string) (*ent.User, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, ErrInvalidToken
	}

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	u, err := s.repo.FindUserByEmailVerificationToken(ctx, tokenHash)
	if err != nil || u == nil {
		return nil, ErrInvalidToken
	}

	if err := s.repo.MarkUserEmailVerified(ctx, u.ID); err != nil {
		return nil, err
	}

	// Audit Log
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, u.TenantID, u.ID, "user.email_verified", "", "", "")

	return u, nil
}

// ResendVerificationEmail triggers a new verification email for an account if unverified.
func (s *Service) ResendVerificationEmail(ctx context.Context, tenantID string, env string, email string) error {
	u, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)
	if err != nil || u == nil {
		// Return nil to prevent email enumeration attacks
		return nil
	}

	if u.EmailVerified {
		return nil
	}

	return s.SendVerificationEmail(ctx, u)
}

// SendMagicLink generates a 15-minute single-use magic login link and emails it to the user.
// Auto-provisions a new user if no account exists with the provided email address (Option A).
func (s *Service) SendMagicLink(ctx context.Context, tenantID string, env string, email string, name string, userAgent string, ipAddress string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return fmt.Errorf("email is required")
	}

	u, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)
	if err != nil {
		return fmt.Errorf("failed looking up user: %w", err)
	}

	// Auto-provision user if not found (Option A)
	if u == nil {
		userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
		createdUser, err := s.repo.CreateUser(ctx, userID, tenantID, env, email, "", name)
		if err != nil {
			return fmt.Errorf("failed auto-provisioning user for magic link: %w", err)
		}
		u = createdUser
	}

	// Generate 32-byte cryptographically random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed generating random magic link token: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	expiresAt := time.Now().Add(15 * time.Minute)
	if err := s.repo.SetUserMagicLinkToken(ctx, u.ID, tokenHash, expiresAt); err != nil {
		return fmt.Errorf("failed saving magic link token: %w", err)
	}

	baseURL := s.config.AppBaseURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	magicURL := fmt.Sprintf("%s/v1/client/auth/magic-link/verify?token=%s", baseURL, rawToken)

	htmlBody, textBody, err := emailPkg.RenderMagicLinkEmail(emailPkg.MagicLinkEmailData{
		UserName:         u.Name,
		MagicLink:        magicURL,
		AppName:          "Authn Platform",
		ExpiresInMinutes: 15,
	})
	if err != nil {
		return fmt.Errorf("failed rendering magic link email template: %w", err)
	}

	if err := s.emailProvider.Send(ctx, u.Email, "Log in to Authn Platform", htmlBody, textBody); err != nil {
		return fmt.Errorf("failed sending magic link email: %w", err)
	}

	// Audit Log
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, tenantID, u.ID, "user.magic_link_sent", ipAddress, userAgent, "")

	return nil
}

// VerifyMagicLinkToken validates a single-use magic login link token, consumes it, marks email verified, and issues session/tokens.
func (s *Service) VerifyMagicLinkToken(ctx context.Context, rawToken string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, "", "", ErrInvalidToken
	}

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	u, err := s.repo.FindUserByMagicLinkToken(ctx, tokenHash)
	if err != nil || u == nil {
		return nil, "", "", ErrInvalidToken
	}

	// Immediately clear single-use token to prevent replay attacks
	if err := s.repo.ClearUserMagicLinkToken(ctx, u.ID); err != nil {
		return nil, "", "", fmt.Errorf("failed consuming magic link token: %w", err)
	}

	// Implicitly verify email address upon magic link click
	if !u.EmailVerified {
		_ = s.repo.MarkUserEmailVerified(ctx, u.ID)
		u.EmailVerified = true
	}

	// Issue Session & Refresh Token
	sessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	rawRefreshToken := hex.EncodeToString(func() []byte {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return b
	}())

	hRef := sha256.Sum256([]byte(rawRefreshToken))
	refHash := hex.EncodeToString(hRef[:])

	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if _, err := s.repo.CreateSession(ctx, sessionID, u.ID, refHash, userAgent, ipAddress, expiresAt); err != nil {
		return nil, "", "", fmt.Errorf("failed creating magic link session: %w", err)
	}

	// Generate Access Token (JWT)
	accessToken, err := jwt.IssueAccessToken(u.ID, u.TenantID, string(u.Environment), u.Email, u.Name, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	_ = s.repo.UpdateUserLastSignIn(ctx, u.ID)

	// Audit Log
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, u.TenantID, u.ID, "user.magic_link_login", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// ValidatePasswordCredentials checks password credentials and issues a login session.
func (s *Service) ValidatePasswordCredentials(ctx context.Context, tenantID string, env string, email string, password string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	u, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)
	if err != nil || u == nil {
		return nil, "", "", ErrInvalidCredentials
	}

	if u.PasswordHash == "" || !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
		return nil, "", "", ErrInvalidCredentials
	}

	// Check if user has active 2FA methods (TOTP, Passkeys, or Recovery Codes)
	var allowedMethods []string

	activeTOTP, err := s.repo.GetActiveTOTPMethodForUser(ctx, u.ID)
	if err == nil && activeTOTP != nil {
		allowedMethods = append(allowedMethods, "totp")
	}

	passkeys, err := s.repo.GetPasskeysForUser(ctx, u.ID)
	if err == nil && len(passkeys) > 0 {
		allowedMethods = append(allowedMethods, "passkey")
	}

	activeSMS, err := s.repo.GetActiveSMSMethodForUser(ctx, u.ID)
	if err == nil && activeSMS != nil {
		allowedMethods = append(allowedMethods, "sms")
	}

	recCount, err := s.repo.GetActiveRecoveryCodeCountForUser(ctx, u.ID)
	if err == nil && recCount > 0 {
		allowedMethods = append(allowedMethods, "backup_code")
	}

	if len(allowedMethods) > 0 {
		mfaToken, err := jwt.IssueMFAChallengeToken(u.ID, tenantID, env, allowedMethods, s.config.AuthnEncryptionKey)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed issuing 2FA challenge token: %w", err)
		}
		return u, mfaToken, "", Err2FARequired
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", "", fmt.Errorf("failed generating refresh token: %w", err)
	}
	rawRefreshToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_, err = s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt)
	if err != nil {
		return nil, "", "", err
	}

	// Issue 15-minute JWT Access Token
	accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	// Update last sign in & Audit Log
	_ = s.repo.UpdateUserLastSignIn(ctx, u.ID)
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, tenantID, u.ID, "user.signed_in", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// RotateRefreshTokenSession validates a raw refresh token (via SHA-256 hash match),
// enforces the 10-second rotation grace period for concurrent requests,
// detects token reuse/theft (revoking all user sessions if reuse occurs past grace period),
// and issues a new 15-minute JWT access token + newly rotated refresh token.
func (s *Service) RotateRefreshTokenSession(ctx context.Context, rawRefreshToken string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	if rawRefreshToken == "" {
		return nil, "", "", fmt.Errorf("refresh token is required")
	}

	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sess, err := s.repo.FindSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed querying session: %w", err)
	}
	if sess == nil {
		return nil, "", "", fmt.Errorf("invalid or expired refresh token")
	}

	// 1. Check if token is active
	if sess.Status == session.StatusActive {
		if time.Now().After(sess.ExpiresAt) {
			return nil, "", "", fmt.Errorf("session expired")
		}

		u, err := s.repo.FindUserByID(ctx, sess.UserID)
		if err != nil || u == nil {
			return nil, "", "", fmt.Errorf("user not found for session")
		}
		if u.Status != "active" {
			return nil, "", "", fmt.Errorf("user account is suspended or banned")
		}

		// Generate new 32-byte opaque refresh token
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err != nil {
			return nil, "", "", fmt.Errorf("failed generating rotated refresh token: %w", err)
		}
		newRawRefreshToken := hex.EncodeToString(tokenBytes)
		newHash := sha256.Sum256([]byte(newRawRefreshToken))
		newTokenHash := hex.EncodeToString(newHash[:])

		newSessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
		expiresAt := time.Now().Add(30 * 24 * time.Hour)

		// Create new active session
		_, err = s.repo.CreateSession(ctx, newSessionID, u.ID, newTokenHash, userAgent, ipAddress, expiresAt)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed creating rotated session: %w", err)
		}

		// Transition old session to 'rotated_grace' with 10-second grace window
		_ = s.repo.MarkSessionRotatedWithGrace(ctx, sess.ID, newSessionID, 10*time.Second)

		// Issue new 15-minute access token
		tenantID := string(u.TenantID)
		env := string(u.Environment)
		accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.config.AuthnEncryptionKey)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
		}

		return u, accessToken, newRawRefreshToken, nil
	}

	// 2. Check if token is in 10-second grace window ('rotated_grace')
	if sess.Status == session.StatusRotatedGrace {
		if sess.GraceExpiresAt != nil && time.Now().Before(*sess.GraceExpiresAt) {
			// Token reused within 10s grace period (e.g. concurrent in-flight requests)
			// Return a fresh access token for the superseded session
			if sess.SupersededBySessionID != nil && *sess.SupersededBySessionID != "" {
				supersededSess, err := s.repo.FindSessionByID(ctx, *sess.SupersededBySessionID)
				if err == nil && supersededSess != nil && supersededSess.Status == session.StatusActive {
					u, err := s.repo.FindUserByID(ctx, supersededSess.UserID)
					if err == nil && u != nil {
						tenantID := string(u.TenantID)
						env := string(u.Environment)
						accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.config.AuthnEncryptionKey)
						if err == nil {
							return u, accessToken, "", nil
						}
					}
				}
			}
		}

		// Grace window EXPIRED! Token reuse detected past 10s grace window -> TOKEN THEFT ALERT!
		fmt.Printf("[SECURITY ALERT] POSSIBLE REFRESH TOKEN THEFT DETECTED: Reuse of rotated token (session ID %s, user ID %s) past 10s grace window. Revoking all user sessions.\n", sess.ID, sess.UserID)
		_ = s.repo.RevokeAllSessionsForUser(ctx, sess.UserID)
		return nil, "", "", fmt.Errorf("invalid_grant: refresh token reuse detected - all sessions revoked for security")
	}

	// 3. Token is revoked -> Revoke all sessions for security
	fmt.Printf("[SECURITY ALERT] POSSIBLE REFRESH TOKEN THEFT DETECTED: Attempted use of revoked session (session ID %s, user ID %s). Revoking all user sessions.\n", sess.ID, sess.UserID)
	_ = s.repo.RevokeAllSessionsForUser(ctx, sess.UserID)
	return nil, "", "", fmt.Errorf("invalid_grant: session has been revoked")
}

// EnrollTOTP generates a new TOTP secret for a user and stores it in pending state (is_enabled = false).
func (s *Service) EnrollTOTP(ctx context.Context, userID string) (*TOTPEnrollResult, error) {
	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, fmt.Errorf("user not found")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Authn Platform",
		AccountName: u.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("failed generating TOTP key: %w", err)
	}

	encryptedSecret, err := crypto.EncryptAES256GCM(key.Secret(), s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed encrypting TOTP secret: %w", err)
	}

	tfmID := fmt.Sprintf("tfm_%s", uuid.New().String()[:12])
	_, err = s.repo.CreateOrUpdatePendingTOTPSecret(ctx, tfmID, u.ID, encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed saving pending TOTP secret: %w", err)
	}

	return &TOTPEnrollResult{
		Secret: key.Secret(),
		URI:    key.URL(),
	}, nil
}

// ConfirmTOTP verifies the submitted 6-digit TOTP code against pending secret, activates 2FA (is_enabled = true), and auto-generates recovery codes if missing.
func (s *Service) ConfirmTOTP(ctx context.Context, userID string, code string) (*ConfirmTOTPResult, error) {
	tfm, err := s.repo.GetTOTPMethodForUser(ctx, userID)
	if err != nil || tfm == nil || tfm.SecretEncrypted == "" {
		return nil, ErrNoPendingTOTP
	}

	secret, err := crypto.DecryptAES256GCM(tfm.SecretEncrypted, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed decrypting TOTP secret: %w", err)
	}

	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Skew:      1,
		Digits:    otp.DigitsSix,
		Period:    30,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return nil, ErrInvalidTOTPCode
	}

	if err := s.repo.EnableTwoFactorMethod(ctx, tfm.ID); err != nil {
		return nil, err
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(tfm.UserID), userID, "user.2fa_enabled", "", "", "")

	// Check if user already has backup recovery codes
	existingCount, _ := s.repo.GetActiveRecoveryCodeCountForUser(ctx, userID)
	var createdCodes []string
	created := false
	if existingCount == 0 {
		recoveryCodes, err := s.GenerateRecoveryCodes(ctx, userID)
		if err == nil {
			createdCodes = recoveryCodes
			created = true
		}
	}

	return &ConfirmTOTPResult{
		Message:              "2FA TOTP successfully confirmed and activated",
		RecoveryCodes:        createdCodes,
		RecoveryCodesCreated: created,
	}, nil
}

// VerifyTOTP validates a 6-digit code against a user's active TOTP secret with +-1 time step skew window tolerance.
func (s *Service) VerifyTOTP(ctx context.Context, userID string, code string) error {
	tfm, err := s.repo.GetActiveTOTPMethodForUser(ctx, userID)
	if err != nil || tfm == nil || tfm.SecretEncrypted == "" {
		return fmt.Errorf("no active TOTP method configured")
	}

	secret, err := crypto.DecryptAES256GCM(tfm.SecretEncrypted, s.config.AuthnEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed decrypting TOTP secret: %w", err)
	}

	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Skew:      1,
		Digits:    otp.DigitsSix,
		Period:    30,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return ErrInvalidTOTPCode
	}

	_ = s.repo.UpdateTwoFactorMethodLastUsed(ctx, tfm.ID)
	return nil
}

// VerifyTOTPChallenge verifies a 2FA challenge code during login using an mfa_token and optional targetMethod.
func (s *Service) VerifyTOTPChallenge(ctx context.Context, mfaToken string, code string, targetMethod string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	claims, err := jwt.VerifyMFAChallengeToken(mfaToken, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", ErrInvalidToken
	}

	if err := s.Verify2FACodeWithMethod(ctx, claims.Sub, claims.Methods, code, targetMethod); err != nil {
		return nil, "", "", err
	}

	u, err := s.repo.FindUserByID(ctx, claims.Sub)
	if err != nil || u == nil {
		return nil, "", "", ErrInvalidToken
	}

	// Issue Session & Refresh Token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", "", fmt.Errorf("failed generating refresh token: %w", err)
	}
	rawRefreshToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if _, err := s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt); err != nil {
		return nil, "", "", err
	}

	accessToken, err := jwt.IssueAccessToken(u.ID, string(u.TenantID), string(u.Environment), u.Email, u.Name, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	_ = s.repo.UpdateUserLastSignIn(ctx, u.ID)
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), u.ID, "user.signed_in_2fa", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// DisableTOTP re-verifies current password with Argon2id, removes TOTP method, and revokes all active sessions for security.
func (s *Service) DisableTOTP(ctx context.Context, userID string, password string, userAgent string, ipAddress string) error {
	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return fmt.Errorf("user not found")
	}

	// Real Argon2id password re-verification
	if u.PasswordHash == "" || !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
		return ErrInvalidCredentials
	}

	tfm, err := s.repo.GetTOTPMethodForUser(ctx, userID)
	if err != nil || tfm == nil {
		return fmt.Errorf("no TOTP method configured")
	}

	if err := s.repo.DeleteTwoFactorMethod(ctx, tfm.ID); err != nil {
		return err
	}

	// Security requirement: Revoke all active user sessions on 2FA removal
	if err := s.repo.RevokeAllSessionsForUser(ctx, userID); err != nil {
		log.Printf("[AuthService] Warning: Failed revoking sessions on 2FA disable for user %s: %v", userID, err)
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), userID, "user.2fa_disabled", ipAddress, userAgent, "")

	return nil
}

// isValidE164Phone helper checks if a phone number string is in valid E.164 format (+ followed by 7-15 digits).
func isValidE164Phone(phone string) bool {
	if !strings.HasPrefix(phone, "+") {
		return false
	}
	digits := phone[1:]
	if len(digits) < 7 || len(digits) > 15 {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// checkSMSRateLimit enforces a maximum of 3 OTP requests per 10-minute window for a user.
func (s *Service) checkSMSRateLimit(userID string) error {
	now := time.Now()
	val, ok := s.smsRateLimits.Load(userID)
	if !ok {
		s.smsRateLimits.Store(userID, smsRateLimitEntry{Count: 1, WindowEnd: now.Add(10 * time.Minute)})
		return nil
	}

	entry := val.(smsRateLimitEntry)
	if now.After(entry.WindowEnd) {
		s.smsRateLimits.Store(userID, smsRateLimitEntry{Count: 1, WindowEnd: now.Add(10 * time.Minute)})
		return nil
	}

	if entry.Count >= 3 {
		return ErrTooManySMSRequests
	}

	entry.Count++
	s.smsRateLimits.Store(userID, entry)
	return nil
}

// BeginSMSEnrollment sends a 6-digit OTP code via SMS (or Email fallback) and stores a pending SMS 2FA record.
func (s *Service) BeginSMSEnrollment(ctx context.Context, userID string, phoneNumber string) error {
	phoneNumber = strings.TrimSpace(phoneNumber)
	if !isValidE164Phone(phoneNumber) {
		return fmt.Errorf("invalid phone number: must be in E.164 format (e.g. +12025550199)")
	}

	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return fmt.Errorf("user not found")
	}

	if err := s.checkSMSRateLimit(userID); err != nil {
		return err
	}

	otpBuf := make([]byte, 4)
	_, _ = rand.Read(otpBuf)
	otpNum := binary.BigEndian.Uint32(otpBuf) % 1000000
	code := fmt.Sprintf("%06d", otpNum)

	s.pendingSMSOTPs.Store(userID, SMSOTPState{
		PhoneNumber: phoneNumber,
		Code:        code,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})

	encryptedPhone, err := crypto.EncryptAES256GCM(phoneNumber, s.config.AuthnEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed encrypting phone number: %w", err)
	}

	if _, err := s.repo.CreateOrUpdatePendingSMSMethod(ctx, userID, encryptedPhone); err != nil {
		return fmt.Errorf("failed creating pending SMS 2FA record: %w", err)
	}

	msg := fmt.Sprintf("Your Authn verification code is: %s", code)
	var smsErr error
	if s.smsProvider != nil {
		smsErr = s.smsProvider.SendSMS(ctx, phoneNumber, msg)
	} else {
		smsErr = fmt.Errorf("no SMS provider configured")
	}

	if smsErr != nil {
		log.Printf("⚠️ SMS send notice for user %s (%s): %v. Falling back to Email OTP.", userID, phoneNumber, smsErr)
		htmlBody := fmt.Sprintf("<p>Your 2FA verification code is: <strong>%s</strong> (expires in 5 minutes)</p>", code)
		textBody := fmt.Sprintf("Your 2FA verification code is: %s (expires in 5 minutes)", code)
		if err := s.emailProvider.Send(ctx, u.Email, "Your Authn 2FA Verification Code", htmlBody, textBody); err != nil {
			return fmt.Errorf("failed sending OTP via SMS and email fallback: %w", err)
		}
	}

	return nil
}

// ConfirmSMSEnrollment verifies a 6-digit SMS OTP, activates the method, sets phone_verified = true, and auto-generates recovery codes if first 2FA method.
func (s *Service) ConfirmSMSEnrollment(ctx context.Context, userID string, code string) (*ConfirmTOTPResult, error) {
	val, ok := s.pendingSMSOTPs.Load(userID)
	if !ok {
		return nil, ErrSMSOTPExpired
	}
	state := val.(SMSOTPState)
	if time.Now().After(state.ExpiresAt) || state.Code != strings.TrimSpace(code) {
		return nil, ErrSMSOTPExpired
	}

	s.pendingSMSOTPs.Delete(userID)

	tfm, err := s.repo.GetSMSMethodForUser(ctx, userID)
	if err != nil || tfm == nil {
		return nil, fmt.Errorf("no pending SMS 2FA enrollment found")
	}

	if err := s.repo.EnableTwoFactorMethod(ctx, tfm.ID); err != nil {
		return nil, fmt.Errorf("failed enabling SMS 2FA method: %w", err)
	}

	if err := s.repo.UpdateUserPhone(ctx, userID, state.PhoneNumber, true); err != nil {
		return nil, fmt.Errorf("failed setting user phone verified: %w", err)
	}

	primaryCount, err := s.repo.CountActivePrimary2FAMethods(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed checking primary 2FA methods: %w", err)
	}

	var recoveryCodes []string
	if primaryCount == 1 {
		codes, err := s.GenerateRecoveryCodes(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("failed generating recovery codes: %w", err)
		}
		recoveryCodes = codes
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, "", userID, "user.sms_2fa_confirmed", "", "", "")

	return &ConfirmTOTPResult{
		Message:              "SMS 2FA successfully confirmed and activated",
		RecoveryCodes:        recoveryCodes,
		RecoveryCodesCreated: len(recoveryCodes) > 0,
	}, nil
}

// DisableSMS2FA re-verifies password with Argon2id, removes SMS method, sets phone_verified = false, and revokes all active sessions.
func (s *Service) DisableSMS2FA(ctx context.Context, userID string, password string, userAgent string, ipAddress string) error {
	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return fmt.Errorf("user not found")
	}

	if u.PasswordHash == "" || !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
		return ErrInvalidCredentials
	}

	tfm, err := s.repo.GetSMSMethodForUser(ctx, userID)
	if err != nil || tfm == nil {
		return fmt.Errorf("no SMS 2FA method configured")
	}

	if err := s.repo.DeleteTwoFactorMethod(ctx, tfm.ID); err != nil {
		return err
	}

	_ = s.repo.UpdateUserPhone(ctx, userID, u.PhoneNumber, false)

	if err := s.repo.RevokeAllSessionsForUser(ctx, userID); err != nil {
		log.Printf("[AuthService] Warning: Failed revoking sessions on SMS 2FA disable for user %s: %v", userID, err)
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), userID, "user.sms_2fa_disabled", ipAddress, userAgent, "")

	return nil
}

// Verify2FACode verifies 2FA code for a user within an authenticated session, accepting optional targetMethod.
func (s *Service) Verify2FACode(ctx context.Context, userID string, code string, targetMethod ...string) error {
	method := ""
	if len(targetMethod) > 0 {
		method = targetMethod[0]
	}
	return s.Verify2FACodeWithMethod(ctx, userID, nil, code, method)
}

// Verify2FACodeWithMethod verifies a 2FA code against specific method or resolves ambiguity according to explicit rules.
func (s *Service) Verify2FACodeWithMethod(ctx context.Context, userID string, allowedMethods []string, code string, targetMethod string) error {
	code = strings.TrimSpace(code)
	targetMethod = strings.ToLower(strings.TrimSpace(targetMethod))

	if len(allowedMethods) == 0 {
		activeTOTP, _ := s.repo.GetActiveTOTPMethodForUser(ctx, userID)
		passkeys, _ := s.repo.GetPasskeysForUser(ctx, userID)
		activeSMS, _ := s.repo.GetActiveSMSMethodForUser(ctx, userID)
		recCount, _ := s.repo.GetActiveRecoveryCodeCountForUser(ctx, userID)

		if activeTOTP != nil {
			allowedMethods = append(allowedMethods, "totp")
		}
		if len(passkeys) > 0 {
			allowedMethods = append(allowedMethods, "passkey")
		}
		if activeSMS != nil {
			allowedMethods = append(allowedMethods, "sms")
		}
		if recCount > 0 {
			allowedMethods = append(allowedMethods, "backup_code")
		}
	}

	// 1. If method is omitted:
	if targetMethod == "" {
		if len(allowedMethods) > 1 {
			return ErrAmbiguous2FAMethod
		}
		if len(allowedMethods) == 1 {
			targetMethod = allowedMethods[0]
		} else {
			return fmt.Errorf("no active 2FA methods found for user")
		}
	}

	// 2. Verify strictly against targetMethod
	switch targetMethod {
	case "sms":
		val, ok := s.pendingSMSOTPs.Load(userID)
		if !ok {
			return ErrSMSOTPExpired
		}
		state := val.(SMSOTPState)
		if time.Now().After(state.ExpiresAt) || state.Code != code {
			return ErrSMSOTPExpired
		}
		s.pendingSMSOTPs.Delete(userID)
		if tfm, err := s.repo.GetActiveSMSMethodForUser(ctx, userID); err == nil && tfm != nil {
			_ = s.repo.UpdateTwoFactorMethodLastUsed(ctx, tfm.ID)
		}
		return nil

	case "totp":
		return s.VerifyTOTP(ctx, userID, code)

	case "backup_code":
		return s.VerifyRecoveryCode(ctx, userID, code)

	default:
		return fmt.Errorf("unsupported 2FA verification method '%s'", targetMethod)
	}
}

// GenerateRecoveryCodes generates 16 cryptographically random human-typeable recovery codes (e.g. 4K7P-9M2N),
// invalidates any previous recovery codes for the user, stores their Argon2id hashes, and returns the raw codes.
// Note for type="backup_code": secret_encrypted stores an Argon2id one-way password hash (RFC 9106 t=3, m=64MB, p=4), NOT reversible encrypted data.
func (s *Service) GenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	_ = s.repo.DeleteAllRecoveryCodesForUser(ctx, userID)

	charset := "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	rawCodes := make([]string, 16)
	hashes := make([]string, 16)

	for i := 0; i < 16; i++ {
		codeBuf := make([]byte, 8)
		if _, err := rand.Read(codeBuf); err != nil {
			return nil, fmt.Errorf("failed generating random code bytes: %w", err)
		}
		var formatted strings.Builder
		var normalized strings.Builder
		for j := 0; j < 8; j++ {
			if j == 4 {
				formatted.WriteRune('-')
			}
			idx := int(codeBuf[j]) % len(charset)
			char := rune(charset[idx])
			formatted.WriteRune(char)
			normalized.WriteRune(char)
		}
		rawCodes[i] = formatted.String()

		// Argon2id one-way password hash (t=3, m=64MB, p=4) per RFC 9106
		// Note for type="backup_code": secret_encrypted stores an Argon2id one-way password hash, NOT reversible encrypted data.
		hash, err := crypto.HashPasswordArgon2id(normalized.String())
		if err != nil {
			return nil, fmt.Errorf("failed hashing recovery code with Argon2id: %w", err)
		}
		hashes[i] = hash
	}

	if err := s.repo.CreateBatchRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}

	return rawCodes, nil
}

// VerifyRecoveryCode verifies a human-submitted recovery code using Argon2id against stored hashes and marks it consumed.
func (s *Service) VerifyRecoveryCode(ctx context.Context, userID string, rawCode string) error {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(rawCode), "-", ""))
	if normalized == "" {
		return ErrInvalidRecoveryCode
	}

	codes, err := s.repo.GetRecoveryCodesForUser(ctx, userID)
	if err != nil || len(codes) == 0 {
		return ErrInvalidRecoveryCode
	}

	var matchedItem *ent.TwoFactorMethod
	for _, item := range codes {
		if item.SecretEncrypted != "" && crypto.VerifyPasswordArgon2id(normalized, item.SecretEncrypted) {
			matchedItem = item
			break
		}
	}

	if matchedItem == nil {
		return ErrInvalidRecoveryCode
	}

	if !matchedItem.IsEnabled {
		return ErrRecoveryCodeAlreadyUsed
	}

	if err := s.repo.MarkRecoveryCodeConsumed(ctx, matchedItem.ID); err != nil {
		return err
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, "", userID, "user.recovery_code_used", "", "", "")

	return nil
}

// RegenerateRecoveryCodes requires Argon2id password step-up, invalidates all old recovery codes, and issues 16 fresh codes.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID string, password string) ([]string, error) {
	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Password re-verification using Argon2id
	if u.PasswordHash == "" || !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	codes, err := s.GenerateRecoveryCodes(ctx, userID)
	if err != nil {
		return nil, err
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), userID, "user.recovery_codes_regenerated", "", "", "")

	return codes, nil
}

// GetRecoveryCodesStatus returns the remaining unused count of recovery codes for a user.
func (s *Service) GetRecoveryCodesStatus(ctx context.Context, userID string) (*RecoveryCodesStatusResult, error) {
	remaining, err := s.repo.GetActiveRecoveryCodeCountForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &RecoveryCodesStatusResult{
		RemainingCount:   remaining,
		TotalCount:       16,
		HasRecoveryCodes: remaining > 0,
	}, nil
}

// convertTwoFactorMethodToWebAuthnCredential converts an ent.TwoFactorMethod into a webauthn.Credential.
func convertTwoFactorMethodToWebAuthnCredential(tfm *ent.TwoFactorMethod) webauthn.Credential {
	credID, err := base64.RawURLEncoding.DecodeString(tfm.CredentialID)
	if err != nil || len(credID) == 0 {
		credID = []byte(tfm.CredentialID)
	}

	var transports []protocol.AuthenticatorTransport
	var flags webauthn.CredentialFlags
	if tfm.WebauthnMetadata != nil {
		if rawTransports, ok := tfm.WebauthnMetadata["transports"].([]interface{}); ok {
			for _, t := range rawTransports {
				if s, ok := t.(string); ok {
					transports = append(transports, protocol.AuthenticatorTransport(s))
				}
			}
		}
		if flagsMap, ok := tfm.WebauthnMetadata["flags"].(map[string]interface{}); ok {
			// NEW & RECENT CREDENTIALS: Use the exact real flags captured during registration.
			if up, ok := flagsMap["user_present"].(bool); ok {
				flags.UserPresent = up
			}
			if uv, ok := flagsMap["user_verified"].(bool); ok {
				flags.UserVerified = uv
			}
			if be, ok := flagsMap["backup_eligible"].(bool); ok {
				flags.BackupEligible = be
			}
			if bs, ok := flagsMap["backup_state"].(bool); ok {
				flags.BackupState = bs
			}
		} else {
			// LEGACY CREDENTIALS ONLY: "flags" key is absent in webauthn_metadata (enrolled prior to flag serialization).
			flags.BackupEligible = true
			flags.BackupState = true
			flags.UserPresent = true
			flags.UserVerified = true
		}
	} else {
		// LEGACY CREDENTIALS ONLY: webauthn_metadata is NULL (enrolled prior to metadata tracking).
		flags.BackupEligible = true
		flags.BackupState = true
		flags.UserPresent = true
		flags.UserVerified = true
	}

	return webauthn.Credential{
		ID:        credID,
		PublicKey: tfm.PublicKey,
		Authenticator: webauthn.Authenticator{
			SignCount: tfm.SignCount,
		},
		Flags:     flags,
		Transport: transports,
	}
}

// BeginWebAuthnRegistration generates WebAuthn PublicKeyCredentialCreationOptions for an authenticated user.
func (s *Service) BeginWebAuthnRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error) {
	if s.webauthn == nil {
		return nil, "", fmt.Errorf("webauthn service is not configured")
	}

	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, "", fmt.Errorf("user not found")
	}

	passkeys, err := s.repo.GetPasskeysForUser(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("failed fetching passkeys: %w", err)
	}

	creds := make([]webauthn.Credential, len(passkeys))
	for i, p := range passkeys {
		creds[i] = convertTwoFactorMethodToWebAuthnCredential(p)
	}

	adapter := &WebAuthnUserAdapter{User: u, Credentials: creds}
	options, sessionData, err := s.webauthn.BeginRegistration(adapter)
	if err != nil {
		return nil, "", fmt.Errorf("failed beginning WebAuthn registration: %w", err)
	}

	sessionID := fmt.Sprintf("wasess_%s", uuid.New().String()[:12])
	s.webauthnSessions.Store(sessionID, sessionData)

	return options, sessionID, nil
}

// FinishWebAuthnRegistration verifies the browser's attestation response, stores the WebAuthn credential, and auto-generates recovery codes if missing.
func (s *Service) FinishWebAuthnRegistration(ctx context.Context, userID string, sessionID string, r *http.Request, passkeyName string) (*ConfirmTOTPResult, error) {
	if s.webauthn == nil {
		return nil, fmt.Errorf("webauthn service is not configured")
	}

	val, ok := s.webauthnSessions.Load(sessionID)
	if !ok {
		return nil, ErrInvalidToken
	}
	sessionData := val.(*webauthn.SessionData)
	s.webauthnSessions.Delete(sessionID)

	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, fmt.Errorf("user not found")
	}

	passkeys, err := s.repo.GetPasskeysForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed fetching passkeys: %w", err)
	}

	creds := make([]webauthn.Credential, len(passkeys))
	for i, p := range passkeys {
		creds[i] = convertTwoFactorMethodToWebAuthnCredential(p)
	}

	adapter := &WebAuthnUserAdapter{User: u, Credentials: creds}
	parsedCredential, err := s.webauthn.FinishRegistration(adapter, *sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("failed finishing WebAuthn registration: %w", err)
	}

	credIDStr := base64.RawURLEncoding.EncodeToString(parsedCredential.ID)
	aaguidStr := hex.EncodeToString(parsedCredential.Authenticator.AAGUID[:])
	metadata := map[string]interface{}{
		"aaguid":           aaguidStr,
		"attestation_type": string(parsedCredential.AttestationType),
		"transports":       parsedCredential.Transport,
		"flags": map[string]interface{}{
			"user_present":    parsedCredential.Flags.UserPresent,
			"user_verified":   parsedCredential.Flags.UserVerified,
			"backup_eligible": parsedCredential.Flags.BackupEligible,
			"backup_state":    parsedCredential.Flags.BackupState,
		},
	}

	_, err = s.repo.CreateWebAuthnPasskey(ctx, userID, passkeyName, credIDStr, parsedCredential.PublicKey, parsedCredential.Authenticator.SignCount, metadata)
	if err != nil {
		return nil, err
	}

	// Auto-generate recovery codes if user does not have any yet
	existingCount, _ := s.repo.GetActiveRecoveryCodeCountForUser(ctx, userID)
	var createdCodes []string
	created := false
	if existingCount == 0 {
		recoveryCodes, err := s.GenerateRecoveryCodes(ctx, userID)
		if err == nil {
			createdCodes = recoveryCodes
			created = true
		}
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), userID, "user.passkey_registered", "", "", "")

	return &ConfirmTOTPResult{
		Message:              "WebAuthn passkey registered successfully",
		RecoveryCodes:        createdCodes,
		RecoveryCodesCreated: created,
	}, nil
}

// BeginWebAuthnLogin generates WebAuthn PublicKeyCredentialRequestOptions for an mfa_token challenge flow.
func (s *Service) BeginWebAuthnLogin(ctx context.Context, mfaToken string) (*protocol.CredentialAssertion, string, string, error) {
	if s.webauthn == nil {
		return nil, "", "", fmt.Errorf("webauthn service is not configured")
	}

	claims, err := jwt.VerifyMFAChallengeToken(mfaToken, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", ErrInvalidToken
	}

	u, err := s.repo.FindUserByID(ctx, claims.Sub)
	if err != nil || u == nil {
		return nil, "", "", ErrInvalidToken
	}

	passkeys, err := s.repo.GetPasskeysForUser(ctx, u.ID)
	if err != nil || len(passkeys) == 0 {
		return nil, "", "", fmt.Errorf("no registered WebAuthn passkeys found for user")
	}

	creds := make([]webauthn.Credential, len(passkeys))
	for i, p := range passkeys {
		creds[i] = convertTwoFactorMethodToWebAuthnCredential(p)
	}

	adapter := &WebAuthnUserAdapter{User: u, Credentials: creds}
	options, sessionData, err := s.webauthn.BeginLogin(adapter)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed beginning WebAuthn login: %w", err)
	}

	sessionID := fmt.Sprintf("wasess_%s", uuid.New().String()[:12])
	s.webauthnSessions.Store(sessionID, sessionData)

	return options, sessionID, u.ID, nil
}

// FinishWebAuthnLogin verifies the browser's assertion response, checks signature counter regression (clone detection), and issues session tokens.
func (s *Service) FinishWebAuthnLogin(ctx context.Context, mfaToken string, sessionID string, r *http.Request, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	if s.webauthn == nil {
		return nil, "", "", fmt.Errorf("webauthn service is not configured")
	}

	claims, err := jwt.VerifyMFAChallengeToken(mfaToken, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", ErrInvalidToken
	}

	val, ok := s.webauthnSessions.Load(sessionID)
	if !ok {
		return nil, "", "", ErrInvalidToken
	}
	sessionData := val.(*webauthn.SessionData)
	s.webauthnSessions.Delete(sessionID)

	u, err := s.repo.FindUserByID(ctx, claims.Sub)
	if err != nil || u == nil {
		return nil, "", "", ErrInvalidToken
	}

	passkeys, err := s.repo.GetPasskeysForUser(ctx, u.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed fetching passkeys: %w", err)
	}

	creds := make([]webauthn.Credential, len(passkeys))
	for i, p := range passkeys {
		creds[i] = convertTwoFactorMethodToWebAuthnCredential(p)
	}

	adapter := &WebAuthnUserAdapter{User: u, Credentials: creds}
	parsedCredential, err := s.webauthn.FinishLogin(adapter, *sessionData, r)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed finishing WebAuthn login: %w", err)
	}

	// Signature Counter Clone Check: counter must be strictly greater than stored count (if stored count > 0)
	credIDStr := base64.RawURLEncoding.EncodeToString(parsedCredential.ID)
	dbPasskey, err := s.repo.GetPasskeyByCredentialID(ctx, credIDStr)
	if err != nil || dbPasskey == nil {
		return nil, "", "", ErrPasskeyNotFound
	}

	if parsedCredential.Authenticator.SignCount <= dbPasskey.SignCount && dbPasskey.SignCount > 0 {
		return nil, "", "", ErrPasskeyCloneDetected
	}

	// Update signature counter in DB
	if err := s.repo.UpdatePasskeySignCount(ctx, dbPasskey.ID, parsedCredential.Authenticator.SignCount); err != nil {
		return nil, "", "", err
	}

	// Issue Session & Refresh Token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", "", fmt.Errorf("failed generating refresh token: %w", err)
	}
	rawRefreshToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sessionIDStr := fmt.Sprintf("sess_%s", uuid.New().String()[:12])
	sessionTTL := 7 * 24 * time.Hour
	now := time.Now()
	expiresAt := now.Add(sessionTTL)

	if _, err := s.repo.CreateSession(ctx, sessionIDStr, u.ID, tokenHash, userAgent, ipAddress, expiresAt); err != nil {
		return nil, "", "", fmt.Errorf("failed creating user session: %w", err)
	}

	accessToken, err := jwt.IssueAccessToken(u.ID, string(u.TenantID), string(u.Environment), u.Email, u.Name, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), u.ID, "user.login_webauthn", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// ListWebAuthnPasskeys returns all registered passkeys for a user.
func (s *Service) ListWebAuthnPasskeys(ctx context.Context, userID string) ([]PasskeyDTO, error) {
	passkeys, err := s.repo.GetPasskeysForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	dtos := make([]PasskeyDTO, len(passkeys))
	for i, p := range passkeys {
		var lastUsedStr *string
		if p.LastUsedAt != nil {
			formatted := p.LastUsedAt.Format("2006-01-02T15:04:05Z")
			lastUsedStr = &formatted
		}
		dtos[i] = PasskeyDTO{
			ID:           p.ID,
			Name:         p.Name,
			CredentialID: p.CredentialID,
			SignCount:    p.SignCount,
			CreatedAt:    p.CreatedAt.Format("2006-01-02T15:04:05Z"),
			LastUsedAt:   lastUsedStr,
			Metadata:     p.WebauthnMetadata,
		}
	}
	return dtos, nil
}

// DeleteWebAuthnPasskey removes a registered passkey for a user.
// Requires Argon2id password step-up re-verification ONLY IF this is the user's LAST remaining 2FA method.
func (s *Service) DeleteWebAuthnPasskey(ctx context.Context, userID string, passkeyID string, password string) error {
	passkeys, err := s.repo.GetPasskeysForUser(ctx, userID)
	if err != nil {
		return err
	}

	var targetPasskey *ent.TwoFactorMethod
	for _, p := range passkeys {
		if p.ID == passkeyID {
			targetPasskey = p
			break
		}
	}
	if targetPasskey == nil {
		return ErrPasskeyNotFound
	}

	primaryCount, err := s.repo.CountActivePrimary2FAMethods(ctx, userID)
	if err != nil {
		return err
	}

	// If this passkey is the LAST remaining 2FA method, require Argon2id password step-up
	if primaryCount <= 1 {
		u, err := s.repo.FindUserByID(ctx, userID)
		if err != nil || u == nil {
			return fmt.Errorf("user not found")
		}

		if password == "" || u.PasswordHash == "" || !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
			return ErrInvalidCredentials
		}

		if err := s.repo.DeleteTwoFactorMethod(ctx, passkeyID); err != nil {
			return err
		}

		// Revoke all active sessions on 2FA disable for security
		_ = s.repo.RevokeAllSessionsForUser(ctx, userID)

		auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
		_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), userID, "user.2fa_disabled", "", "", "")
		return nil
	}

	// Multiple 2FA methods remain -> allow deletion without password step-up
	if err := s.repo.DeleteTwoFactorMethod(ctx, passkeyID); err != nil {
		return err
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, "", userID, "user.passkey_deleted", "", "", "")

	return nil
}




