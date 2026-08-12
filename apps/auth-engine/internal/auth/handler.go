/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/handler.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber HTTP handlers for client authentication endpoints (signup, login)
 *              protected by sliding-window rate limiting and password policy validation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/authcookie"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
)

// SignUpRequest defines the HTTP payload for user registration.
type SignUpRequest struct {
	TenantID    string `json:"tenant_id" example:"tnt_demo123"`
	Environment string `json:"environment" example:"test"`
	Email       string `json:"email" example:"user@example.com"`
	Password    string `json:"password" example:"SuperSecret123!"`
	Name        string `json:"name" example:"Alex Smith"`
}

// LoginRequest defines the HTTP payload for password login.
type LoginRequest struct {
	TenantID    string `json:"tenant_id" example:"tnt_demo123"`
	Environment string `json:"environment" example:"test"`
	Email       string `json:"email" example:"user@example.com"`
	Password    string `json:"password" example:"SuperSecret123!"`
}

// AuthResponse defines the successful authentication or 2FA challenge response payload.
type AuthResponse struct {
	User          UserDTO           `json:"user"`
	AccessToken   string            `json:"access_token,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken  string            `json:"refresh_token,omitempty" example:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
	PolicyWarning *PolicyWarningDTO `json:"policy_warning,omitempty"`
	MFARequired   bool              `json:"mfa_required,omitempty"`
	MFAToken      string            `json:"mfa_token,omitempty"`
	Methods       []string          `json:"methods,omitempty"`
}

// PolicyWarningDTO contains password compliance and verification notices returned during login/signup.
type PolicyWarningDTO struct {
	RequiresPasswordUpgrade   bool     `json:"requires_password_upgrade,omitempty"`
	RequiresEmailVerification bool     `json:"requires_email_verification,omitempty"`
	MissingCriteria           []string `json:"missing_criteria,omitempty"`
}

// UserDTO defines the public profile payload returned to clients.
type UserDTO struct {
	ID            string  `json:"id" example:"usr_1a2b3c"`
	Email         string  `json:"email" example:"user@example.com"`
	EmailVerified bool    `json:"email_verified" example:"false"`
	Name          *string `json:"name,omitempty" example:"Alex Smith"`
	Status        string  `json:"status" example:"active"`
	CreatedAt     string  `json:"created_at" example:"2026-08-01T12:00:00Z"`
}

// Handler handles HTTP requests for authentication flows.
type Handler struct {
	service         *Service
	guardianService *GuardianService
	recoveryService *RecoveryService
	policyRepo      *policy.Repository
	rateLimiter     *ratelimit.Limiter
	resendLimiter   *ratelimit.Limiter
	// cookies builds every session cookie this handler writes. It is never nil:
	// NewHandler installs one backed by default tenant policy, and
	// WithSessionPolicyResolver replaces it with one that reads live policy.
	cookies   *authcookie.Writer
	blocklist *tokenblocklist.Blocklist
}

// NewHandler constructs a new Auth Handler instance.
func NewHandler(service *Service, policyRepo *policy.Repository, rateLimiter *ratelimit.Limiter, resendLimiter ...*ratelimit.Limiter) *Handler {
	telemetry := NewTelemetryService(service.repo, "super_secret_kms_key_32bytes_authn!", policyRepo)
	var rLimiter *ratelimit.Limiter
	if len(resendLimiter) > 0 {
		rLimiter = resendLimiter[0]
	}
	return &Handler{
		service:         service,
		guardianService: NewGuardianService(service.repo, policyRepo, service.config),
		recoveryService: NewRecoveryService(service.repo, telemetry, policyRepo),
		policyRepo:      policyRepo,
		rateLimiter:     rateLimiter,
		resendLimiter:   rLimiter,
		cookies:         authcookie.NewWriter(service.config, nil),
	}
}

// WithBlocklist sets the JTI revocation store used by routes this handler
// protects with RequireClientAuth. It returns the handler for chaining.
func (h *Handler) WithBlocklist(bl *tokenblocklist.Blocklist) *Handler {
	h.blocklist = bl
	return h
}


// WithSessionPolicyResolver points cookie construction at a live source of tenant
// session policy, and returns the handler for chaining.
//
// Without it, cookies are built from policy.DefaultSessionPolicy — correct, but
// deaf to a customer who has configured SameSite or a token lifetime. It is a
// separate method rather than a constructor parameter so the handler stays
// constructible in tests that have no database or cache behind them.
func (h *Handler) WithSessionPolicyResolver(r authcookie.SessionPolicyResolver) *Handler {
	h.cookies = authcookie.NewWriter(h.service.config, r)
	return h
}

// RegisterRoutes mounts every client authentication endpoint under /v1/client.
//
// pkMiddleware validates the publishable key and resolves the tenant; it applies to every route
// here and may be nil in tests. The account rate limiter, when configured, runs next, so a
// throttled caller is rejected before any credential is examined.
//
// Authentication is declared per route rather than by group position. Routes built with public()
// carry no bearer requirement; routes built with protected() additionally run RequireClientAuth,
// which is the single implementation of "this caller holds a valid access token" shared with
// /v1/client/user. A route's authentication is therefore visible on its own registration line and
// does not depend on where that line sits relative to a group boundary.
//
// Three groups of routes are deliberately public despite acting on an identity:
//   - the 2FA verify and passkey login routes, which are authorized by the short-lived mfa_token
//     issued after a successful password check, not by a session;
//   - the recovery proof, claim, and token-cancel routes, whose whole purpose is to serve a user
//     who cannot sign in;
//   - the guardian invitation accept route, authorized by the invitation token itself.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware fiber.Handler) {
	api := app.Group("/v1/client")

	var mws []fiber.Handler
	if pkMiddleware != nil {
		mws = append(mws, pkMiddleware)
	}
	if h.rateLimiter != nil {
		mws = append(mws, h.rateLimiter.Middleware())
	}

	// The signing secret is the same one the handlers used to verify with inline, so a token
	// accepted before is accepted now.
	clientAuth := middleware.RequireClientAuth(h.service.config.EncryptionKey, h.blocklist)

	public := func(handler fiber.Handler) []fiber.Handler {
		return append(append([]fiber.Handler{}, mws...), handler)
	}
	protected := func(handler fiber.Handler) []fiber.Handler {
		return append(append(append([]fiber.Handler{}, mws...), clientAuth), handler)
	}

	// Registration, password sign-in and email verification.
	api.Post("/signup", public(h.SignUp)...)
	api.Post("/login", public(h.Login)...)
	api.Get("/verify-email", public(h.VerifyEmail)...)
	api.Post("/resend-verification", public(h.ResendVerification)...)

	// Passwordless magic link (FR-15). The emailed token is the credential.
	api.Post("/auth/magic-link", public(h.SendMagicLink)...)
	api.Get("/auth/magic-link/verify", public(h.VerifyMagicLink)...)
	api.Post("/auth/magic-link/verify", public(h.VerifyMagicLink)...)

	// TOTP second factor (FR-4). Verification is public because it also serves the login
	// challenge, where the caller holds an mfa_token rather than a session.
	api.Post("/2fa/totp/enroll", protected(h.EnrollTOTP)...)
	api.Post("/2fa/totp/confirm", protected(h.ConfirmTOTP)...)
	api.Post("/2fa/totp/disable", protected(h.DisableTOTP)...)
	api.Post("/2fa/totp/verify", public(h.VerifyTOTP)...)
	api.Post("/auth/2fa/verify", public(h.VerifyTOTP)...)

	// SMS OTP second factor (FR-4).
	api.Post("/2fa/sms/enroll", protected(h.EnrollSMS)...)
	api.Post("/2fa/sms/confirm", protected(h.ConfirmSMS)...)
	api.Delete("/2fa/sms/disable", protected(h.DisableSMS)...)

	// Backup recovery codes (FR-4).
	api.Post("/2fa/recovery-codes/regenerate", protected(h.RegenerateRecoveryCodes)...)
	api.Get("/2fa/recovery-codes/status", protected(h.GetRecoveryCodesStatus)...)

	// WebAuthn passkeys (FR-4). Registration needs a session; login is authorized by mfa_token.
	api.Post("/2fa/webauthn/register/begin", protected(h.BeginWebAuthnRegistration)...)
	api.Post("/2fa/webauthn/register/finish", protected(h.FinishWebAuthnRegistration)...)
	api.Post("/2fa/webauthn/login/begin", public(h.BeginWebAuthnLogin)...)
	api.Post("/2fa/webauthn/login/finish", public(h.FinishWebAuthnLogin)...)
	api.Get("/2fa/webauthn/credentials", protected(h.ListWebAuthnPasskeys)...)
	api.Delete("/2fa/webauthn/credentials/:id", protected(h.DeleteWebAuthnPasskey)...)

	// Guardian roster management (FR-5). Accepting an invitation is public: the invitee is a
	// different person from the account holder and generally has no session here.
	api.Post("/account/guardians/invite", protected(h.InviteGuardians)...)
	api.Post("/account/guardians/accept", public(h.AcceptGuardianInvite)...)
	api.Get("/account/guardians", protected(h.ListGuardians)...)
	api.Delete("/account/guardians/:id", protected(h.RevokeGuardian)...)

	// Account recovery (FR-5). Everything except the authenticated cancel is reachable without a
	// session by design — a locked-out user has none.
	api.Post("/auth/recovery/initiate", public(h.InitiateRecovery)...)
	api.Post("/auth/recovery/proof/guardian", public(h.SubmitGuardianProof)...)
	api.Post("/auth/recovery/proof/old-password", public(h.SubmitOldPasswordProof)...)
	api.Post("/auth/recovery/proof/security-questions", public(h.SubmitSecurityQuestionsProof)...)
	api.Post("/auth/recovery/claim", public(h.ClaimAccount)...)
	api.Post("/auth/recovery/cancel", public(h.CancelRecoveryAuth)...)
	api.Post("/auth/recovery/cancel/token", public(h.CancelRecoveryToken)...)
}

// SendMagicLinkDTO defines the request payload for requesting a magic login link.
type SendMagicLinkDTO struct {
	TenantID    string `json:"tenant_id" example:"tnt_demo"`
	Environment string `json:"environment" example:"test"`
	Email       string `json:"email" example:"user@example.com"`
	Name        string `json:"name,omitempty" example:"Alex Smith"`
}

// VerifyMagicLinkDTO defines the request payload for verifying a magic link token.
type VerifyMagicLinkDTO struct {
	Token string `json:"token" example:"raw_token_string"`
}

// msgInvalidClientType is the client-facing message for a rejected
// X-Authn-Client-Type header. The error parseAndValidateClientType returns
// interpolates the caller-supplied header value for server-side diagnostics;
// that value is deliberately NOT reflected back in the response body.
const msgInvalidClientType = "unrecognized X-Authn-Client-Type header: expected 'web', 'native', or 'mobile'"

// parseAndValidateClientType validates and normalizes the X-Authn-Client-Type HTTP header.
func parseAndValidateClientType(c *fiber.Ctx) (string, error) {
	raw := c.Get("X-Authn-Client-Type", "web")
	clientType := strings.ToLower(strings.TrimSpace(raw))
	if clientType == "" {
		clientType = "web"
	}

	switch clientType {
	case "web", "native", "mobile":
		return clientType, nil
	default:
		return "", fmt.Errorf("unrecognized X-Authn-Client-Type header '%s': expected 'web', 'native', or 'mobile'", raw)
	}
}

// isValidEmail checks whether an email address format complies with standard RFC email structure.
func isValidEmail(email string) bool {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil || addr.Address != strings.TrimSpace(email) {
		return false
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return false
	}
	domainParts := strings.Split(parts[1], ".")
	if len(domainParts) < 2 || len(domainParts[len(domainParts)-1]) < 2 {
		return false
	}
	return true
}

// trustedDeviceCookieTTL is how long the device-recognition cookie issued by a
// successful account claim is honoured.
//
// It is deliberately long: the cookie's purpose is to recognise a returning
// device and skip a re-verification step, so a lifetime shorter than the gap
// between sign-ins would defeat it. The cookie is a recognition signal only and
// carries no authority on its own.
const trustedDeviceCookieTTL = 90 * 24 * time.Hour

// clientSafeError maps a known package sentinel to a machine-readable code and a
// message that is safe to return verbatim. Sentinel text is authored for end
// users, so echoing it preserves the wording callers already depend on.
//
// Anything that is NOT a sentinel — a wrapped ent/SQL error, a JWT parse
// failure, an fmt.Errorf carrying a session status or column name — must never
// reach a response body; ok == false signals the caller to fall back to a static
// message. Matching uses errors.Is so a wrapped sentinel still routes correctly.
func clientSafeError(err error) (httperr.Code, string, bool) {
	switch {
	// Credentials and sessions.
	case errors.Is(err, ErrInvalidCredentials):
		return httperr.CodeInvalidCredentials, ErrInvalidCredentials.Error(), true
	case errors.Is(err, ErrUserAlreadyExists):
		return httperr.CodeAlreadyExists, ErrUserAlreadyExists.Error(), true
	case errors.Is(err, ErrEmailVerificationRequired):
		return httperr.CodeEmailVerificationRequired, ErrEmailVerificationRequired.Error(), true
	case errors.Is(err, Err2FARequired):
		return httperr.CodeMFARequired, Err2FARequired.Error(), true
	case errors.Is(err, ErrInvalidToken):
		return httperr.CodeInvalidToken, ErrInvalidToken.Error(), true
	case errors.Is(err, ErrInvalidApiKey):
		return httperr.CodeInvalidToken, ErrInvalidApiKey.Error(), true

	// Second-factor enrollment and verification.
	case errors.Is(err, ErrNoPendingTOTP):
		return httperr.CodeNotFound, ErrNoPendingTOTP.Error(), true
	case errors.Is(err, ErrInvalidTOTPCode):
		return httperr.CodeInvalidMFACode, ErrInvalidTOTPCode.Error(), true
	case errors.Is(err, ErrRecoveryCodeAlreadyUsed):
		return httperr.CodeInvalidMFACode, ErrRecoveryCodeAlreadyUsed.Error(), true
	case errors.Is(err, ErrInvalidRecoveryCode):
		return httperr.CodeInvalidMFACode, ErrInvalidRecoveryCode.Error(), true
	case errors.Is(err, ErrSMSOTPExpired):
		return httperr.CodeInvalidMFACode, ErrSMSOTPExpired.Error(), true
	case errors.Is(err, ErrAmbiguous2FAMethod):
		return httperr.CodeMissingParameter, ErrAmbiguous2FAMethod.Error(), true
	case errors.Is(err, ErrTooManySMSRequests):
		return httperr.CodeRateLimited, ErrTooManySMSRequests.Error(), true
	case errors.Is(err, ErrAdmin2FAMandatory):
		return httperr.CodeForbidden, ErrAdmin2FAMandatory.Error(), true
	case errors.Is(err, ErrPasskeyCloneDetected):
		return httperr.CodeInvalidMFACode, ErrPasskeyCloneDetected.Error(), true
	case errors.Is(err, ErrPasskeyNotFound):
		return httperr.CodeNotFound, ErrPasskeyNotFound.Error(), true

	// Guardian enrollment (FR-5).
	case errors.Is(err, ErrMaxGuardiansExceeded):
		return httperr.CodeValidationFailed, ErrMaxGuardiansExceeded.Error(), true
	case errors.Is(err, ErrGuardianNotFound):
		return httperr.CodeNotFound, ErrGuardianNotFound.Error(), true
	case errors.Is(err, ErrInvalidInviteToken):
		return httperr.CodeInvalidToken, ErrInvalidInviteToken.Error(), true

	// Account recovery (FR-5).
	case errors.Is(err, ErrNoRecoveryMethodsAvailable):
		return httperr.CodeNotFound, ErrNoRecoveryMethodsAvailable.Error(), true
	case errors.Is(err, ErrOriginBlacklisted):
		return httperr.CodeForbidden, ErrOriginBlacklisted.Error(), true
	case errors.Is(err, ErrInvalidCancellationPoint):
		return httperr.CodeInvalidToken, ErrInvalidCancellationPoint.Error(), true
	case errors.Is(err, ErrInvalidRecoveryRequest):
		return httperr.CodeInvalidToken, ErrInvalidRecoveryRequest.Error(), true
	case errors.Is(err, ErrAccountLockedOut):
		return httperr.CodeRateLimited, ErrAccountLockedOut.Error(), true
	case errors.Is(err, ErrHigherTierMethodsNotExhausted):
		return httperr.CodeForbidden, ErrHigherTierMethodsNotExhausted.Error(), true
	case errors.Is(err, ErrInvalidProof):
		return httperr.CodeInvalidCredentials, ErrInvalidProof.Error(), true
	}
	return "", "", false
}

// sendServiceError writes the canonical envelope for a service-layer error
// without ever putting the error's own text in the body.
//
// status is always the status the call site already used — this helper never
// re-routes a response to a different HTTP status. Known sentinels keep their
// user-facing wording; everything else is logged server-side under op and
// answered with the static fallback.
func sendServiceError(c *fiber.Ctx, op string, status int, err error, fallbackCode httperr.Code, fallbackMsg string) error {
	if code, msg, ok := clientSafeError(err); ok {
		return httperr.Send(c, status, code, msg)
	}
	if err != nil {
		log.Printf("[error] %s %s %s: %v", c.Method(), c.Path(), op, err)
	}
	return httperr.Send(c, status, fallbackCode, fallbackMsg)
}

// sendWithDetails writes the canonical envelope plus a small set of extra,
// non-sensitive fields that clients already branch on (missing_criteria,
// retry_after_seconds, email_verified). Extras must never carry internal error
// text — they exist so converting to the envelope does not silently drop a
// documented part of the response contract.
func sendWithDetails(c *fiber.Ctx, status int, code httperr.Code, msg string, details fiber.Map) error {
	body := fiber.Map{"error": msg, "code": string(code)}
	for k, v := range details {
		body[k] = v
	}
	return c.Status(status).JSON(body)
}

// extractBearerToken resolves the caller's access token from the authn_access_token cookie, the
// access_token cookie, or an Authorization: Bearer header, in that order.
func extractBearerToken(c *fiber.Ctx) string {
	if tok := c.Cookies("authn_access_token"); tok != "" {
		return tok
	}
	if tok := c.Cookies("access_token"); tok != "" {
		return tok
	}
	authHeader := c.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// getUserID returns the authenticated user's ID from the locals RequireClientAuth populates.
func getUserID(c *fiber.Ctx) string {
	if val, ok := c.Locals("userID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("user_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// getTenantID returns the tenant the publishable-key middleware resolved for this
// request. An empty string is not an error here: it only means cookie attributes
// fall back to default session policy, which is what a route reached without key
// resolution should get.
func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenant_id").(string); ok {
		return val
	}
	return ""
}

// extractBearerToken resolves the caller's access token from the authn_access_token cookie, the
