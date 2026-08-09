/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/service.go
 * Tier: Internal Feature Package / Auth Service
 *
 * Description: Core authentication domain logic: registration and password sign-in, email
 *              verification and magic links, refresh-token session issuance and rotation, the
 *              second-factor suite (TOTP, SMS OTP, WebAuthn passkeys, backup recovery codes),
 *              and API key validation.
 *
 * Security Notice:
 *   - Passwords and backup recovery codes are hashed with Argon2id (t=3, m=64MB, p=4).
 *   - Refresh tokens and email/magic-link tokens are persisted only as SHA-256 digests, so a
 *     database read yields nothing that can be replayed against this service.
 *   - Token and session lifetimes come from Config; see the default* constants below for the
 *     values applied when a field is left unset.
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	emailPkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	smsPkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Sentinel errors returned by this package. Handlers match them with errors.Is and echo their
// text to callers verbatim, so each message is written for an end user and must stay free of
// internal detail. Anything not listed here is an infrastructure failure and is answered with a
// static message instead.
var (
	// ErrInvalidCredentials covers every failed password check. It is deliberately identical for
	// an unknown address and a wrong password, so it cannot be used to enumerate accounts.
	ErrInvalidCredentials = errors.New("invalid email or password")
	// ErrUserAlreadyExists reports a signup for an address already registered in this tenant and
	// environment.
	ErrUserAlreadyExists = errors.New("user with this email already exists")
	// ErrInvalidApiKey reports an API key that is unknown, revoked, or past its expiry.
	ErrInvalidApiKey = errors.New("invalid or expired api key")
	// ErrInvalidToken reports a single-use token (email verification, magic link, MFA challenge,
	// WebAuthn session) that did not resolve to a live record.
	ErrInvalidToken = errors.New("invalid or revoked token")
	// ErrEmailVerificationRequired reports that tenant policy blocks sign-in until the address is
	// verified.
	ErrEmailVerificationRequired = errors.New("email verification required before signing in")
	// Err2FARequired signals that the password was correct but a second factor is outstanding. It
	// accompanies an MFA challenge token rather than a session.
	Err2FARequired = errors.New("2FA verification required before signing in")
	// ErrNoPendingTOTP reports a confirmation attempt with no enrollment in progress.
	ErrNoPendingTOTP = errors.New("no pending TOTP enrollment found")
	// ErrInvalidTOTPCode reports a code that failed validation within the accepted skew window.
	ErrInvalidTOTPCode = errors.New("invalid 6-digit TOTP code")
	// ErrInvalidRecoveryCode reports a backup code matching no stored hash for the user.
	ErrInvalidRecoveryCode = errors.New("invalid recovery code")
	// ErrRecoveryCodeAlreadyUsed reports a backup code that matched but was already consumed.
	// Distinguished from ErrInvalidRecoveryCode so the user learns to try a different code.
	ErrRecoveryCodeAlreadyUsed = errors.New("this recovery code has already been used")
	// ErrPasskeyCloneDetected reports a signature counter that did not advance, which means the
	// authenticator was cloned or the assertion replayed. The login is refused.
	ErrPasskeyCloneDetected = errors.New("authenticator signature counter regression detected: potential cloned or replayed authenticator")
	// ErrPasskeyNotFound reports a passkey ID that is unknown or owned by another user. The two
	// cases are merged so the ID space cannot be probed.
	ErrPasskeyNotFound = errors.New("passkey not found or does not belong to user")
	// ErrAmbiguous2FAMethod reports that several second factors are active and the caller did not
	// say which one the submitted code belongs to.
	ErrAmbiguous2FAMethod = errors.New("multiple 2FA methods enabled; 'method' field is required to specify which 2FA method to verify")
	// ErrSMSOTPExpired reports an SMS code that is unknown, wrong, or past its window. The cases
	// are merged so a caller cannot tell a wrong code from an expired one.
	ErrSMSOTPExpired = errors.New("SMS OTP verification code has expired or is invalid")
	// ErrTooManySMSRequests reports that the per-user SMS send budget for the current window is
	// spent. It bounds the cost an attacker can impose by triggering paid messages.
	ErrTooManySMSRequests = errors.New("too many OTP requests; please wait before requesting another code")
	// ErrAdmin2FAMandatory reports an attempt to remove the last second factor from an account
	// holding an administrative role, which policy forbids.
	ErrAdmin2FAMandatory = errors.New("2FA is mandatory for administrator accounts and cannot be disabled")
)

// Default token and session lifetimes, applied when the corresponding Config field is left unset.
//
// They mirror the defaults config.Load installs, so a Service built from a partially populated
// Config behaves like one built from a fully loaded environment. The fallback exists because a
// zero duration is not a meaningful setting but a silently destructive one: a zero refresh-token
// lifetime mints sessions that have already expired at the instant they are created.
const (
	defaultRefreshTokenTTL      = 720 * time.Hour
	defaultSessionGracePeriod   = 10 * time.Second
	defaultEmailVerificationTTL = 24 * time.Hour
	defaultMagicLinkTTL         = 15 * time.Minute
	defaultMFAChallengeTTL      = 5 * time.Minute
)

// defaultAppName is the product name applied when Config supplies none. It is the issuer an
// authenticator app shows beside a TOTP entry, so it must never render blank.
const defaultAppName = "Authn Platform"

// Per-user SMS OTP send budget, enforced in process by checkSMSRateLimit.
//
// These are not configuration. The limiter is a per-instance sync.Map with no shared state, so a
// deployment running several instances already enforces a multiple of this budget; exposing it as
// a tunable would imply a precision the mechanism does not have. It exists to cap the cost of
// triggering paid messages, above the Redis-backed request limiter that fronts the route.
const (
	smsOTPMaxPerWindow    = 3
	smsOTPRateLimitWindow = 10 * time.Minute
)

// webAuthnLoginSessionTTL is the session lifetime granted by a passkey login.
//
// It is shorter than Config.RefreshTokenTTL, which governs every other sign-in path, and is held
// here rather than read from configuration so that changing the general session lifetime does not
// silently move it. Treat the divergence as deliberate only for as long as this comment stands: a
// passkey is a stronger credential than a password, so there is no security argument for its
// sessions being shorter, and unifying the two on RefreshTokenTTL would be a lengthening of live
// session lifetimes that needs its own decision.
const webAuthnLoginSessionTTL = 7 * 24 * time.Hour

// SMSOTPState is a pending SMS one-time code held in process between BeginSMSEnrollment and its
// confirmation. Codes are never persisted, so an instance restart cancels enrollments in flight.
type SMSOTPState struct {
	// PhoneNumber is the E.164 destination the code was sent to. It is promoted to the user
	// record only once the code is confirmed.
	PhoneNumber string
	// Code is the plaintext six-digit code, compared verbatim on confirmation.
	Code string
	// ExpiresAt is when the code stops being accepted.
	ExpiresAt time.Time
}

// smsRateLimitEntry tracks one user's SMS send budget within the current window.
type smsRateLimitEntry struct {
	// Count is the number of sends charged so far in this window.
	Count int
	// WindowEnd is when the budget resets; a load past this instant starts a fresh window.
	WindowEnd time.Time
}

// TOTPEnrollResult contains secret and URI returned on 2FA enrollment.
type TOTPEnrollResult struct {
	// Secret is the base32 seed, shown once so it can be typed into an authenticator by hand.
	Secret string `json:"secret"`
	// URI is the otpauth:// provisioning URI the client renders as a QR code.
	URI string `json:"uri"`
}

// ConfirmTOTPResult contains confirmation message and optional auto-generated backup recovery codes.
type ConfirmTOTPResult struct {
	// Message is human-readable confirmation text.
	Message string `json:"message"`
	// RecoveryCodes carries a freshly minted backup code set, present only when this enrollment
	// created one. It is the single opportunity to read the codes; only hashes are stored.
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
	// RecoveryCodesCreated tells the client whether to show the codes, without it having to
	// distinguish an absent slice from an empty one.
	RecoveryCodesCreated bool `json:"recovery_codes_created"`
}

// RecoveryCodesStatusResult contains remaining count of unused recovery codes.
type RecoveryCodesStatusResult struct {
	// RemainingCount is how many codes are still unused.
	RemainingCount int `json:"remaining_count"`
	// TotalCount is the size of a full code set, so a client can render "n of m left".
	TotalCount int `json:"total_count"`
	// HasRecoveryCodes reports whether any code remains.
	HasRecoveryCodes bool `json:"has_recovery_codes"`
}

// PasskeyDTO contains public details of a registered WebAuthn passkey.
type PasskeyDTO struct {
	// ID is the internal two-factor method row ID, used to address the passkey for deletion.
	ID string `json:"id"`
	// Name is the user-supplied label, e.g. "Work YubiKey".
	Name string `json:"name"`
	// CredentialID is the base64url authenticator credential handle.
	CredentialID string `json:"credential_id"`
	// SignCount is the last observed signature counter, which clone detection compares against.
	SignCount uint32 `json:"sign_count"`
	// CreatedAt is when the passkey was registered, RFC 3339 in UTC.
	CreatedAt string `json:"created_at"`
	// LastUsedAt is when the passkey last completed a login, nil if never used since registration.
	LastUsedAt *string `json:"last_used_at,omitempty"`
	// Metadata holds the AAGUID, attestation type, transports and authenticator flags captured at
	// registration, which clients use to name and icon the authenticator.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// WebAuthnUserAdapter implements the webauthn.User interface for an ent.User and its credentials.
type WebAuthnUserAdapter struct {
	// User is the account the ceremony is being run for.
	User *ent.User
	// Credentials are the account's already-registered passkeys, supplied to the library so it
	// can exclude them at registration and match against them at login.
	Credentials []webauthn.Credential
}

// WebAuthnID returns the stable user handle the authenticator stores alongside the credential.
// The account ID is used rather than the email so the handle survives an address change.
func (u *WebAuthnUserAdapter) WebAuthnID() []byte {
	return []byte(u.User.ID)
}

// WebAuthnName returns the account name shown in the authenticator's credential list.
func (u *WebAuthnUserAdapter) WebAuthnName() string {
	return u.User.Email
}

// WebAuthnDisplayName returns the human-friendly name for the browser prompt, falling back to the
// email address for accounts that have no name set.
func (u *WebAuthnUserAdapter) WebAuthnDisplayName() string {
	if u.User.Name != "" {
		return u.User.Name
	}
	return u.User.Email
}

// WebAuthnIcon returns no icon. The field is deprecated in the WebAuthn specification and ignored
// by current browsers.
func (u *WebAuthnUserAdapter) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns the account's registered credentials.
func (u *WebAuthnUserAdapter) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// Service handles domain business logic for authentication.
type Service struct {
	// repo is the persistence boundary for users, sessions, two-factor methods and audit rows.
	repo *Repository
	// config supplies signing secrets and every token lifetime. See the default* constants for
	// the values used when a lifetime is left unset.
	config *config.Config
	// emailProvider delivers verification, magic-link and OTP-fallback mail. Never nil; a noop
	// provider is substituted at construction so call sites need no guard.
	emailProvider emailPkg.EmailProvider
	// smsProvider delivers OTP messages. May be nil, in which case sends fall back to email.
	smsProvider smsPkg.SMSProvider
	// webauthn is the configured relying party. Nil when no RP ID is set, which disables the
	// passkey endpoints rather than failing at startup.
	webauthn *webauthn.WebAuthn
	// webauthnSessions holds in-flight ceremony state by session ID. In process, so a ceremony
	// must finish on the instance that began it.
	webauthnSessions sync.Map
	// pendingSMSOTPs holds unconfirmed SMS codes keyed by user ID, as SMSOTPState.
	pendingSMSOTPs sync.Map
	// smsRateLimits holds per-user SMS send budgets keyed by user ID, as smsRateLimitEntry.
	smsRateLimits sync.Map
}

// NewService creates a new authentication domain service instance.
//
// A nil emailProvider is replaced with a noop provider. smsProviders is variadic so callers may
// inject a stub; when none is given the provider is built from cfg, and any construction failure
// degrades to noop rather than failing, so a deployment with no SMS credentials still starts.
// WebAuthn is initialized only when cfg carries a relying-party ID; otherwise the passkey
// endpoints report that the feature is unconfigured.
func NewService(repo *Repository, cfg *config.Config, emailProvider emailPkg.EmailProvider, smsProviders ...smsPkg.SMSProvider) *Service {
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

// refreshTokenTTL returns how long a newly created session may be refreshed before the user must
// sign in again, falling back to defaultRefreshTokenTTL when Config leaves it unset.
func (s *Service) refreshTokenTTL() time.Duration {
	if s.config != nil && s.config.RefreshTokenTTL > 0 {
		return s.config.RefreshTokenTTL
	}
	return defaultRefreshTokenTTL
}

// sessionGracePeriod returns how long a just-rotated refresh token keeps working, falling back to
// defaultSessionGracePeriod when Config leaves it unset.
//
// The window exists so requests already in flight when a rotation lands are not all logged out. A
// zero value would make every concurrent refresh look like token theft.
func (s *Service) sessionGracePeriod() time.Duration {
	if s.config != nil && s.config.SessionGracePeriod > 0 {
		return s.config.SessionGracePeriod
	}
	return defaultSessionGracePeriod
}

// emailVerificationTTL returns the lifetime of an email verification link, falling back to
// defaultEmailVerificationTTL when Config leaves it unset.
func (s *Service) emailVerificationTTL() time.Duration {
	if s.config != nil && s.config.EmailVerificationTTL > 0 {
		return s.config.EmailVerificationTTL
	}
	return defaultEmailVerificationTTL
}

// magicLinkTTL returns the lifetime of a passwordless sign-in link, falling back to
// defaultMagicLinkTTL when Config leaves it unset. The link alone grants a session, which is why
// the window is short.
func (s *Service) magicLinkTTL() time.Duration {
	if s.config != nil && s.config.MagicLinkTTL > 0 {
		return s.config.MagicLinkTTL
	}
	return defaultMagicLinkTTL
}

// mfaChallengeTTL returns how long a second-factor challenge stays open — both the token issued
// after a successful password check and the SMS code sent during enrollment — falling back to
// defaultMFAChallengeTTL when Config leaves it unset.
func (s *Service) mfaChallengeTTL() time.Duration {
	if s.config != nil && s.config.MFAChallengeTTL > 0 {
		return s.config.MFAChallengeTTL
	}
	return defaultMFAChallengeTTL
}

// appName returns the product name shown to users: in outbound mail, and as the issuer label an
// authenticator app displays beside a TOTP entry. Falls back to defaultAppName when Config leaves
// it unset.
func (s *Service) appName() string {
	if s.config != nil && s.config.AppName != "" {
		return s.config.AppName
	}
	return defaultAppName
}

// ValidateApiKey resolves a raw publishable (pk_...) or secret (sk_...) API key to its stored
// record and returns that record.
//
// The key is looked up by HMAC-SHA256 digest under the configured pepper, so the database holds
// no material an attacker could present. It returns ErrInvalidApiKey for a blank key, a digest
// matching no row, a revoked key, and an expired one alike — the cases are merged so a caller
// cannot distinguish "never existed" from "withdrawn".
func (s *Service) ValidateApiKey(ctx context.Context, rawKey string) (*ent.ApiKey, error) {
	if rawKey == "" {
		return nil, ErrInvalidApiKey
	}

	h := hmac.New(sha256.New, []byte(s.config.APIKeyPepper))
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

// SignUpWithPassword registers an account and signs it straight in, returning the new user, a
// JWT access token, and the raw refresh token. The refresh token is returned here and nowhere
// else; only its SHA-256 digest is stored.
//
// The first account in a tenant atomically claims the tenant_admin role, so exactly one of any
// number of concurrent signups wins it. A failed claim is not fatal — the account is created as a
// regular user, since refusing to register someone because a role query failed is the worse
// outcome. Verification mail is likewise best-effort: a delivery failure is logged and the signup
// still succeeds, leaving the account unverified.
//
// It returns ErrUserAlreadyExists when the address is already registered in this tenant and
// environment, and a wrapped error when tenant setup, password hashing, entropy, account
// creation, session creation, or token signing fails — in which case no account exists.
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

	// Atomically claim the tenant_admin role for the first user in this tenant.
	// ClaimFirstAdminRole issues a conditional UPDATE at the DB level:
	//   UPDATE tenants SET first_admin_claimed = true WHERE id = ? AND first_admin_claimed = false
	// Only one concurrent signup can win (n=1 rows affected). All others get n=0.
	// This eliminates the TOCTOU race that existed with the previous count-then-create approach.
	claimed, err := s.repo.ClaimFirstAdminRole(ctx, tenantID)
	if err != nil {
		// Non-fatal: log and default to regular user if the claim query fails.
		log.Printf("[AuthService] Warning: could not claim first admin role for tenant %s: %v", tenantID, err)
		claimed = false
	}
	role := ""
	if claimed {
		role = "tenant_admin"
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
	expiresAt := time.Now().Add(s.refreshTokenTTL())
	_, err = s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt)
	if err != nil {
		return nil, "", "", err
	}

	// Issue 15-minute JWT Access Token (role embedded for console auth)
	accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, role, s.config.EncryptionKey, s.config.AccessTokenTTL)
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

// SendVerificationEmail mints a 32-byte verification token for u, stores only its SHA-256 digest
// against the account, and emails the user a link carrying the raw token.
//
// It returns a wrapped error when entropy is unavailable or the template fails to render, the
// repository's error when the digest cannot be stored, and the provider's error when delivery
// fails. A delivery failure leaves the token live, so a later resend is not required for the link
// already in flight to work.
func (s *Service) SendVerificationEmail(ctx context.Context, u *ent.User) error {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed generating verification token: %w", err)
	}
	rawToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])

	ttl := s.emailVerificationTTL()
	expiresAt := time.Now().Add(ttl)
	if err := s.repo.SetUserEmailVerificationToken(ctx, u.ID, tokenHash, expiresAt); err != nil {
		return err
	}

	verifyURL := fmt.Sprintf("%s/v1/client/verify-email?token=%s", s.config.AppBaseURL, rawToken)

	htmlBody, textBody, err := emailPkg.RenderVerificationEmail(emailPkg.VerificationEmailData{
		UserName:         u.Name,
		VerificationLink: verifyURL,
		AppName:          s.appName(),
		// Derived from the same TTL as the stored expiry, so the mail cannot promise a window
		// the token does not honour.
		ExpiresInHours: int(ttl.Hours()),
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

// SendMagicLink mints a single-use sign-in link, stores only its SHA-256 digest against the
// account, and emails the raw token to the user. The link's lifetime is Config.MagicLinkTTL.
//
// An address with no account is provisioned one with no password, so a magic link doubles as
// registration. This means the endpoint must stay behind a rate limiter: it creates rows for
// arbitrary caller-supplied addresses.
//
// It returns an error for a blank address, and a wrapped error when the lookup, provisioning,
// entropy, token storage, template rendering, or delivery fails. The audit record is
// best-effort. Nothing here reveals whether the address already had an account.
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

	ttl := s.magicLinkTTL()
	expiresAt := time.Now().Add(ttl)
	if err := s.repo.SetUserMagicLinkToken(ctx, u.ID, tokenHash, expiresAt); err != nil {
		return fmt.Errorf("failed saving magic link token: %w", err)
	}

	baseURL := s.config.AppBaseURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	magicURL := fmt.Sprintf("%s/v1/client/auth/magic-link/verify?token=%s", baseURL, rawToken)

	htmlBody, textBody, err := emailPkg.RenderMagicLinkEmail(emailPkg.MagicLinkEmailData{
		UserName:  u.Name,
		MagicLink: magicURL,
		AppName:   s.appName(),
		// Derived from the same TTL as the stored expiry, so the mail cannot promise a window
		// the token does not honour.
		ExpiresInMinutes: int(ttl.Minutes()),
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

// VerifyMagicLinkToken redeems a magic-link token and returns the user with a fresh access token
// and raw refresh token.
//
// The token is cleared before any session is created, so a token that raced two requests is spent
// exactly once. Clicking the link also marks the address verified: possession of mail sent to it
// is the same proof the verification flow asks for.
//
// It returns ErrInvalidToken for a blank token or one matching no live record, and a wrapped
// error when consuming the token, creating the session, or signing the access token fails.
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

	expiresAt := time.Now().Add(s.refreshTokenTTL())
	if _, err := s.repo.CreateSession(ctx, sessionID, u.ID, refHash, userAgent, ipAddress, expiresAt); err != nil {
		return nil, "", "", fmt.Errorf("failed creating magic link session: %w", err)
	}

	// Generate Access Token (JWT)
	accessToken, err := jwt.IssueAccessTokenWithSession(u.ID, u.TenantID, string(u.Environment), u.Email, u.Name, s.ResolveRoleClaim(ctx, u.ID), sessionID, s.config.EncryptionKey, s.config.AccessTokenTTL)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	_ = s.repo.UpdateUserLastSignIn(ctx, u.ID)

	// Audit Log
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, u.TenantID, u.ID, "user.magic_link_login", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// ValidatePasswordCredentials verifies a password and, when no second factor is enrolled, issues
// a session — returning the user, an access token, and the raw refresh token.
//
// When the account has any second factor enrolled it returns Err2FARequired together with the
// user and an MFA challenge token in the access-token position, and an empty refresh token. That
// sentinel is the normal 2FA path, not a failure; callers must branch on it before treating the
// error as a rejection.
//
// Argon2id verification runs against a dummy hash when the account is missing or has no password,
// so the hit and miss paths cost the same and cannot be told apart by timing. It returns
// ErrInvalidCredentials for an unknown address, a wrong password, and a lookup failure alike, and
// a plain error naming the status for an account that is not active.
func (s *Service) ValidatePasswordCredentials(ctx context.Context, tenantID string, env string, email string, password string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	u, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)

	// Execute constant-time password verification using DummyArgon2idHash if user is missing or has no password hash.
	// Prevents side-channel timing attacks that allow user enumeration (~160ms CPU cost in both cases).
	passwordHash := crypto.DummyArgon2idHash
	if u != nil && u.PasswordHash != "" {
		passwordHash = u.PasswordHash
	}

	validPassword := crypto.VerifyPasswordArgon2id(password, passwordHash)

	if err != nil || u == nil || !validPassword {
		return nil, "", "", ErrInvalidCredentials
	}

	if u.Status != "active" {
		return nil, "", "", fmt.Errorf("account is locked or suspended (status: %s)", u.Status)
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
		mfaToken, err := jwt.IssueMFAChallengeToken(u.ID, tenantID, env, allowedMethods, s.config.EncryptionKey)
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
	expiresAt := time.Now().Add(s.refreshTokenTTL())
	_, err = s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt)
	if err != nil {
		return nil, "", "", err
	}

	// Issue 15-minute JWT Access Token
	accessToken, err := jwt.IssueAccessTokenWithSession(u.ID, tenantID, env, u.Email, u.Name, s.ResolveRoleClaim(ctx, u.ID), sessionID, s.config.EncryptionKey, s.config.AccessTokenTTL)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	// Update last sign in & Audit Log
	_ = s.repo.UpdateUserLastSignIn(ctx, u.ID)
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, tenantID, u.ID, "user.signed_in", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// RotateRefreshTokenSession exchanges a raw refresh token for a new session, returning the user,
// a fresh access token, and the rotated refresh token.
//
// Rotation is single-use: the presented session moves to rotated_grace and a new one takes its
// place. Reuse within Config.SessionGracePeriod is treated as a concurrent in-flight request and
// answered with a fresh access token for the superseding session, with an empty refresh token —
// the caller keeps the token it already rotated to.
//
// Reuse after that window, or use of an already-revoked session, is treated as theft: every
// session for the account is revoked and an error is returned. That is deliberately drastic,
// because a token presented twice means two parties hold it and there is no way to tell which is
// the owner.
//
// It returns a plain error for a blank token, a token matching no session, an expired session, a
// missing user, or a suspended account, and a wrapped error when entropy, session creation, or
// token signing fails.
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
		expiresAt := time.Now().Add(s.refreshTokenTTL())

		// Create new active session
		_, err = s.repo.CreateSession(ctx, newSessionID, u.ID, newTokenHash, userAgent, ipAddress, expiresAt)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed creating rotated session: %w", err)
		}

		// Transition old session to 'rotated_grace' with 10-second grace window
		_ = s.repo.MarkSessionRotatedWithGrace(ctx, sess.ID, newSessionID, s.sessionGracePeriod())

		// Issue new 15-minute access token
		tenantID := string(u.TenantID)
		env := string(u.Environment)
		accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.ResolveRoleClaim(ctx, u.ID), s.config.EncryptionKey, s.config.AccessTokenTTL)
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
						accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.ResolveRoleClaim(ctx, u.ID), s.config.EncryptionKey, s.config.AccessTokenTTL)
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

// EnrollTOTP mints a TOTP secret for a user and returns it with its provisioning URI.
//
// The secret is stored encrypted and disabled, so an abandoned enrollment never counts as an
// active second factor; ConfirmTOTP is what enables it. Re-enrolling replaces any pending secret.
// It returns a plain error when the user does not exist, and a wrapped error when key generation,
// encryption, or storage fails.
func (s *Service) EnrollTOTP(ctx context.Context, userID string) (*TOTPEnrollResult, error) {
	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, fmt.Errorf("user not found")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.appName(),
		AccountName: u.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("failed generating TOTP key: %w", err)
	}

	encryptedSecret, err := crypto.EncryptAES256GCM(key.Secret(), s.config.EncryptionKey)
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

// ConfirmTOTP validates a code against the pending secret and, on success, activates TOTP.
//
// Enabling a first second factor also mints a backup code set when the account has none, returned
// in the result and readable only here. Code generation is best-effort: a failure leaves TOTP
// enabled with no backup codes rather than failing a confirmed enrollment.
//
// It returns ErrNoPendingTOTP when no enrollment is in progress, ErrInvalidTOTPCode when the code
// does not validate within the skew window, and a wrapped error when decryption or the enable
// write fails.
func (s *Service) ConfirmTOTP(ctx context.Context, userID string, code string) (*ConfirmTOTPResult, error) {
	tfm, err := s.repo.GetTOTPMethodForUser(ctx, userID)
	if err != nil || tfm == nil || tfm.SecretEncrypted == "" {
		return nil, ErrNoPendingTOTP
	}

	secret, err := crypto.DecryptAES256GCM(tfm.SecretEncrypted, s.config.EncryptionKey)
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

// VerifyAdminPassword re-checks a user's password for step-up authentication, returning nil when
// it matches. It returns ErrInvalidCredentials for an unknown user, an account with no password,
// and a wrong password alike.
func (s *Service) VerifyAdminPassword(ctx context.Context, userID string, password string) error {
	u, err := s.repo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return ErrInvalidCredentials
	}
	if u.PasswordHash == "" || !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
		return ErrInvalidCredentials
	}
	return nil
}

// VerifyAdminTOTP re-checks a user's TOTP code for step-up authentication. It is an alias for
// VerifyTOTP and returns the same errors.
func (s *Service) VerifyAdminTOTP(ctx context.Context, userID string, code string) error {
	return s.VerifyTOTP(ctx, userID, code)
}

// VerifyTOTP validates a code against the user's active TOTP secret, returning nil on success.
//
// One 30-second step of skew either side is accepted, which tolerates ordinary clock drift
// between the authenticator and this server. It returns a plain error when no active method is
// configured, ErrInvalidTOTPCode when the code does not validate, and a wrapped error when the
// stored secret cannot be decrypted. The last-used timestamp is updated best-effort.
func (s *Service) VerifyTOTP(ctx context.Context, userID string, code string) error {
	tfm, err := s.repo.GetActiveTOTPMethodForUser(ctx, userID)
	if err != nil || tfm == nil || tfm.SecretEncrypted == "" {
		return fmt.Errorf("no active TOTP method configured")
	}

	secret, err := crypto.DecryptAES256GCM(tfm.SecretEncrypted, s.config.EncryptionKey)
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

// VerifyTOTPChallenge completes a login that stopped at the second factor, returning the user, an
// access token, and the raw refresh token.
//
// The challenge token carries the methods the account is permitted to use, so the set of
// acceptable factors is fixed at password time and cannot be widened by the caller. targetMethod
// selects among them and may be empty when only one is allowed.
//
// It returns ErrInvalidToken for a challenge token that does not verify or whose subject no
// longer exists, whatever error the factor check produced (ErrInvalidTOTPCode,
// ErrSMSOTPExpired, ErrInvalidRecoveryCode, ErrAmbiguous2FAMethod), and a wrapped error when
// entropy, session creation, or token signing fails.
func (s *Service) VerifyTOTPChallenge(ctx context.Context, mfaToken string, code string, targetMethod string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	claims, err := jwt.VerifyMFAChallengeToken(mfaToken, s.config.EncryptionKey)
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
	expiresAt := time.Now().Add(s.refreshTokenTTL())
	if _, err := s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt); err != nil {
		return nil, "", "", err
	}

	accessToken, err := jwt.IssueAccessToken(u.ID, string(u.TenantID), string(u.Environment), u.Email, u.Name, s.ResolveRoleClaim(ctx, u.ID), s.config.EncryptionKey, s.config.AccessTokenTTL)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	_ = s.repo.UpdateUserLastSignIn(ctx, u.ID)
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), u.ID, "user.signed_in_2fa", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// ResolveRoleClaim returns the console role slug to embed in a user's JWT
// `role` claim, or "" if the user holds no console-admin role.
//
// Thin wrapper over rbac.ResolveConsoleRoleClaim, which is the single source of
// truth shared with the OAuth, social and session token paths. Deliberately
// narrower than IsAdminUser, which answers the broader "is this user privileged
// in any way" question used to protect admins from impersonation.
func (s *Service) ResolveRoleClaim(ctx context.Context, userID string) string {
	return rbac.ResolveConsoleRoleClaim(ctx, s.repo.factory.GetClient(ctx, "", ""), userID)
}

// IsAdminUser reports whether the user holds any administrative role.
//
// It answers the broad "is this account privileged" question used to keep admins from being
// stripped of their last second factor, and is deliberately wider than ResolveRoleClaim, which
// only names console roles. A query failure yields false, so a lookup outage cannot fabricate
// privilege.
func (s *Service) IsAdminUser(ctx context.Context, userID string) bool {
	client := s.repo.factory.GetClient(ctx, "", "")
	userRoles, err := client.UserRole.Query().
		Where(userrole.UserID(userID)).
		WithRole().
		All(ctx)
	if err == nil {
		for _, ur := range userRoles {
			if ur.Edges.Role != nil {
				slug := ur.Edges.Role.Slug
				if slug == "tenant_admin" || slug == "admin" || slug == "super_admin" || slug == "org_admin" || slug == "support_admin" {
					return true
				}
			}
		}
	}
	return false
}

// DisableTOTP removes a user's TOTP method after re-checking their password, and revokes every
// active session.
//
// Sessions are dropped because removing a factor is exactly what an attacker holding a stolen
// session would do, and the legitimate user re-authenticating is a cheap price. It returns a
// plain error when the user or method is missing, ErrInvalidCredentials when the password does
// not match, and ErrAdmin2FAMandatory when this is the last factor on an administrative account.
// Session revocation failure is logged, not returned: the method is already gone.
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

	// Security Policy: Admins cannot disable 2FA if it is their only active primary 2FA method
	activeCount, err := s.repo.CountActivePrimary2FAMethods(ctx, userID)
	if err == nil && activeCount <= 1 && s.IsAdminUser(ctx, userID) {
		return ErrAdmin2FAMandatory
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

// isValidE164Phone reports whether phone is syntactically E.164: a leading "+" followed by 7 to
// 15 digits. It is a shape check only and says nothing about whether the number is reachable.
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

// checkSMSRateLimit charges one SMS send against the user's budget, returning nil when the send
// may proceed and ErrTooManySMSRequests when the budget for the current window is spent.
//
// The window is fixed rather than sliding: the first send of a window starts it, and the budget
// resets wholesale once it lapses. State is per-instance and in memory, so a restart clears every
// budget; see smsOTPMaxPerWindow for why that is acceptable here.
func (s *Service) checkSMSRateLimit(userID string) error {
	now := time.Now()
	val, ok := s.smsRateLimits.Load(userID)
	if !ok {
		s.smsRateLimits.Store(userID, smsRateLimitEntry{Count: 1, WindowEnd: now.Add(smsOTPRateLimitWindow)})
		return nil
	}

	entry := val.(smsRateLimitEntry)
	if now.After(entry.WindowEnd) {
		s.smsRateLimits.Store(userID, smsRateLimitEntry{Count: 1, WindowEnd: now.Add(smsOTPRateLimitWindow)})
		return nil
	}

	if entry.Count >= smsOTPMaxPerWindow {
		return ErrTooManySMSRequests
	}

	entry.Count++
	s.smsRateLimits.Store(userID, entry)
	return nil
}

// BeginSMSEnrollment sends a six-digit code to phoneNumber and records a pending, disabled SMS
// method for the user. The code lives for Config.MFAChallengeTTL and is held in memory only.
//
// A send failure falls back to emailing the code, so a misconfigured or failing SMS provider does
// not strand enrollment. The number is stored encrypted and is promoted to the user record only
// once ConfirmSMSEnrollment succeeds.
//
// It returns a plain error for a non-E.164 number or an unknown user, ErrTooManySMSRequests when
// the send budget is spent, and a wrapped error when encryption, the pending-record write, or
// both delivery paths fail.
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

	ttl := s.mfaChallengeTTL()
	s.pendingSMSOTPs.Store(userID, SMSOTPState{
		PhoneNumber: phoneNumber,
		Code:        code,
		ExpiresAt:   time.Now().Add(ttl),
	})

	encryptedPhone, err := crypto.EncryptAES256GCM(phoneNumber, s.config.EncryptionKey)
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
		// The stated window is derived from the TTL actually applied above.
		expiresIn := int(ttl.Minutes())
		htmlBody := fmt.Sprintf("<p>Your 2FA verification code is: <strong>%s</strong> (expires in %d minutes)</p>", code, expiresIn)
		textBody := fmt.Sprintf("Your 2FA verification code is: %s (expires in %d minutes)", code, expiresIn)
		if err := s.emailProvider.Send(ctx, u.Email, "Your Authn 2FA Verification Code", htmlBody, textBody); err != nil {
			return fmt.Errorf("failed sending OTP via SMS and email fallback: %w", err)
		}
	}

	return nil
}

// ConfirmSMSEnrollment validates the pending code and, on success, activates the SMS method and
// marks the phone number verified.
//
// The code is consumed before the method is enabled, so a resubmission cannot be replayed. When
// this is the account's first second factor a backup code set is minted and returned, readable
// only here.
//
// It returns ErrSMSOTPExpired when no code is pending, the code is wrong, or it has lapsed — the
// three are merged so a caller cannot tell them apart — and a wrapped error when the pending
// record is missing or any of the enable, phone, or code-generation writes fail.
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

// DisableSMS2FA removes a user's SMS method after re-checking their password, clears the
// phone-verified flag, and revokes every active session for the same reason DisableTOTP does.
//
// It returns a plain error when the user or method is missing and ErrInvalidCredentials when the
// password does not match. Session revocation failure is logged, not returned.
//
// Unlike DisableTOTP this does not enforce ErrAdmin2FAMandatory, so an administrator whose only
// second factor is SMS can remove it.
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

// Verify2FACode validates a second-factor code for an already-authenticated user, resolving the
// account's active methods itself. targetMethod is optional and selects among them. It returns
// the errors listed on Verify2FACodeWithMethod.
func (s *Service) Verify2FACode(ctx context.Context, userID string, code string, targetMethod ...string) error {
	method := ""
	if len(targetMethod) > 0 {
		method = targetMethod[0]
	}
	return s.Verify2FACodeWithMethod(ctx, userID, nil, code, method)
}

// Verify2FACodeWithMethod validates code against exactly one second-factor method, returning nil
// on success.
//
// allowedMethods bounds what may be used and comes from the MFA challenge token during login;
// when empty the account's currently active methods are resolved instead. targetMethod picks one
// of them, and may be omitted only when a single method is allowed — otherwise the caller must
// say which factor the code belongs to rather than have the server try each in turn, which would
// let one code be tested against every method.
//
// It returns ErrAmbiguous2FAMethod when the method is omitted with several available, a plain
// error when none is available or targetMethod is unsupported, and otherwise the verifying
// method's own error: ErrSMSOTPExpired, ErrInvalidTOTPCode, ErrInvalidRecoveryCode, or
// ErrRecoveryCodeAlreadyUsed.
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

// GenerateRecoveryCodes replaces a user's backup codes with 16 fresh ones and returns them in
// plaintext. This is the only time they are readable; only Argon2id hashes are stored.
//
// Codes are drawn from an alphabet with no visually ambiguous characters (no 0/O, 1/I) and
// formatted in two groups of four, because these are transcribed by hand under stress. The
// stored-hash column is named secret_encrypted for consistency with the other method types, but
// for backup codes it holds a one-way hash, not recoverable ciphertext.
//
// Existing codes are deleted first, so a partial failure can leave the account with no usable
// codes. It returns a wrapped error when entropy or hashing fails, and the repository's error
// when the batch write fails.
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

// VerifyRecoveryCode validates a backup code and marks it consumed, returning nil on success.
//
// Input is upper-cased with dashes stripped before comparison, so the formatting shown to the
// user does not have to be reproduced exactly. Every stored hash is tried, which costs one
// Argon2id verification per code held.
//
// It returns ErrInvalidRecoveryCode for a blank code, an account with no codes, and a code
// matching nothing; ErrRecoveryCodeAlreadyUsed when the code matched but was previously spent;
// and the repository's error when marking it consumed fails.
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

// RegenerateRecoveryCodes re-checks the user's password and replaces their backup codes,
// returning the new set in plaintext. Every previous code stops working.
//
// The password step-up matters because these codes bypass the second factor: without it, anyone
// holding a live session could mint themselves a permanent way past MFA. It returns a plain error
// when the user is missing, ErrInvalidCredentials when the password does not match, and
// GenerateRecoveryCodes' error otherwise.
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

// GetRecoveryCodesStatus reports how many backup codes the user has left, without exposing any
// code value. It returns the repository's error when the count query fails.
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

// convertTwoFactorMethodToWebAuthnCredential adapts a stored passkey row into the credential
// shape the WebAuthn library expects.
//
// A credential ID that is not valid base64url is passed through as raw bytes, which keeps
// credentials enrolled before the encoding was normalized usable. Rows carrying no authenticator
// flags are assumed to be present, verified, backup-eligible and backed up; that assumption is
// permissive, so it must not be relied on for any security decision — clone detection uses the
// signature counter, which is always stored.
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

// BeginWebAuthnRegistration starts a passkey enrollment, returning the creation options for the
// browser and the session ID that FinishWebAuthnRegistration must be given.
//
// Already-registered credentials are passed to the library so the authenticator excludes them and
// the user cannot enroll the same key twice. Ceremony state is held in memory on this instance,
// so the finish call must reach the same process.
//
// It returns a plain error when WebAuthn is unconfigured or the user is missing, and a wrapped
// error when the passkey read or the library call fails.
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

// FinishWebAuthnRegistration verifies the browser's attestation and stores the new passkey.
//
// The ceremony session is consumed before verification, so a replayed finish call finds nothing
// and fails. Authenticator flags are captured at registration and persisted, since they cannot be
// recovered later. A first second factor also mints a backup code set, returned in the result and
// best-effort as elsewhere.
//
// It returns a plain error when WebAuthn is unconfigured or the user is missing, ErrInvalidToken
// for an unknown or already-consumed session ID, and a wrapped error when attestation
// verification or the credential write fails.
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

// BeginWebAuthnLogin starts a passkey assertion for a login already past the password step,
// returning the request options, the ceremony session ID, and the user ID.
//
// Authorization comes entirely from the MFA challenge token, which names the account, so this is
// not a bearer-authenticated call. It returns a plain error when WebAuthn is unconfigured or the
// account has no passkeys, ErrInvalidToken when the challenge token does not verify or its
// subject is missing, and a wrapped error when the library call fails.
func (s *Service) BeginWebAuthnLogin(ctx context.Context, mfaToken string) (*protocol.CredentialAssertion, string, string, error) {
	if s.webauthn == nil {
		return nil, "", "", fmt.Errorf("webauthn service is not configured")
	}

	claims, err := jwt.VerifyMFAChallengeToken(mfaToken, s.config.EncryptionKey)
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

// FinishWebAuthnLogin verifies a passkey assertion and issues a session, returning the user, an
// access token, and the raw refresh token.
//
// The signature counter must strictly advance for any credential that has ever reported a
// non-zero one; a counter that stalls or goes backwards means the authenticator was cloned or the
// assertion replayed, and the login is refused. Authenticators that always report zero are exempt
// because the counter is optional in the specification.
//
// Sessions from this path last webAuthnLoginSessionTTL rather than Config.RefreshTokenTTL. It
// returns ErrInvalidToken for a bad challenge token or an unknown ceremony session,
// ErrPasskeyNotFound when the asserted credential is not on file, ErrPasskeyCloneDetected on a
// counter regression, and a wrapped error when assertion verification, the counter update,
// session creation, or token signing fails.
func (s *Service) FinishWebAuthnLogin(ctx context.Context, mfaToken string, sessionID string, r *http.Request, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	if s.webauthn == nil {
		return nil, "", "", fmt.Errorf("webauthn service is not configured")
	}

	claims, err := jwt.VerifyMFAChallengeToken(mfaToken, s.config.EncryptionKey)
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
	sessionTTL := webAuthnLoginSessionTTL
	now := time.Now()
	expiresAt := now.Add(sessionTTL)

	if _, err := s.repo.CreateSession(ctx, sessionIDStr, u.ID, tokenHash, userAgent, ipAddress, expiresAt); err != nil {
		return nil, "", "", fmt.Errorf("failed creating user session: %w", err)
	}

	accessToken, err := jwt.IssueAccessToken(u.ID, string(u.TenantID), string(u.Environment), u.Email, u.Name, s.ResolveRoleClaim(ctx, u.ID), s.config.EncryptionKey, s.config.AccessTokenTTL)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, string(u.TenantID), u.ID, "user.login_webauthn", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// ListWebAuthnPasskeys returns the user's registered passkeys as public DTOs, carrying no key
// material. It returns an empty slice for an account with none, and the repository's error when
// the read fails.
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

// DeleteWebAuthnPasskey removes one of a user's passkeys.
//
// Deleting a passkey while others remain needs no extra proof. Deleting the last remaining second
// factor does: it requires a password step-up and revokes every session, because that operation
// is indistinguishable from an attacker with a stolen session dismantling the account's defences.
//
// It returns ErrPasskeyNotFound when the ID is unknown or belongs to another user,
// ErrInvalidCredentials when the last-factor step-up fails or no password was supplied, and the
// repository's error when a read or the delete fails.
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
