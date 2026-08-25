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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/authcookie"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
)

// SignUpRequest defines the HTTP payload for user registration.
type SignUpRequest struct {
	// TenantID and Environment are populated from the credential that
	// authenticated the request, not from the body. They are excluded from JSON so
	// a caller cannot name a tenant or reach live data with a test key.
	TenantID    string `json:"-"`
	Environment string `json:"-"`
	Email       string `json:"email" example:"user@example.com"`
	Password    string `json:"password" example:"SuperSecret123!"`
	Name        string `json:"name" example:"Alex Smith"`
	// Username is the optional public handle. Omitted or empty registers an account
	// without one, which stays a valid account: it signs in by address, and a handle
	// can be claimed later from the profile endpoint.
	Username string `json:"username" example:"alexsmith"`
}

// maxIdentifierBytes bounds a sign-in identifier, at the RFC 5321 ceiling on an
// email address — the longer of the two things the field may hold, since a handle
// stops at username.MaxLength. It is a resource guard rather than a validation rule:
// the value reaches a database query, and refusing an over-long one costs nothing a
// real user would notice.
const maxIdentifierBytes = 320

// LoginRequest defines the HTTP payload for password login.
type LoginRequest struct {
	// TenantID and Environment are populated from the credential that
	// authenticated the request, not from the body. They are excluded from JSON so
	// a caller cannot name a tenant or reach live data with a test key.
	TenantID    string `json:"-"`
	Environment string `json:"-"`
	// Identifier is the email address or username the account is named by. Email is
	// accepted as an alias for it so a caller written against the address-only form
	// keeps working; Identifier wins when both are sent.
	Identifier string `json:"identifier" example:"alexsmith"`
	Email      string `json:"email" example:"user@example.com"`
	Password   string `json:"password" example:"SuperSecret123!"`
}

// LoginIdentifier returns the identifier the request names the account by,
// preferring the explicit field over the alias.
func (r LoginRequest) LoginIdentifier() string {
	if strings.TrimSpace(r.Identifier) != "" {
		return strings.TrimSpace(r.Identifier)
	}
	return strings.TrimSpace(r.Email)
}

// UsernameAvailabilityResponse answers whether one handle can be registered.
//
// Reason and Message are empty on an available handle, and Suggestions is omitted
// there too: a client that received alternatives alongside "yes" would have to know
// to ignore them.
type UsernameAvailabilityResponse struct {
	// Username echoes the handle that was checked, so a client rendering a
	// late-arriving response can discard one that no longer matches the field.
	Username  string `json:"username" example:"alexsmith"`
	Available bool   `json:"available" example:"false"`
	// Reason is invalid, reserved or taken. It is the field to branch on; Message is
	// for display and its wording is not part of the contract.
	Reason      string   `json:"reason,omitempty" example:"taken"`
	Message     string   `json:"message,omitempty" example:"that username is already taken"`
	Suggestions []string `json:"suggestions,omitempty" example:"alexsmith1,alex_smith,asmith"`
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
	// Username is the public handle in the form the user typed it, omitted when they
	// hold none. Lookups use the canonical form; this is the display value.
	Username  string `json:"username,omitempty" example:"AlexSmith"`
	Status    string `json:"status" example:"active"`
	CreatedAt string `json:"created_at" example:"2026-08-01T12:00:00Z"`
}

// newUserDTO projects a user row onto the client-facing payload.
//
// Every authentication response is built through this, so one account cannot be
// described differently by two endpoints. Assembling the struct at each call site is
// how the magic-link response came to omit status and created_at that its
// password-login sibling returned, and how a field added later gets missed on
// whichever handler the author was not editing.
//
// Name is a pointer so an unset one is absent rather than an empty string, which is
// the distinction its existing consumers read. Username needs no pointer: the empty
// string is not a handle anyone can hold, so omitempty already means "none".
func newUserDTO(u *ent.User) UserDTO {
	var namePtr *string
	if u.Name != "" {
		namePtr = &u.Name
	}

	return UserDTO{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          namePtr,
		Username:      Handle(u),
		Status:        string(u.Status),
		CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// Handler handles HTTP requests for authentication flows.
type Handler struct {
	service         *Service
	guardianService *GuardianService
	recoveryService *RecoveryService
	policyRepo      *policy.Repository
	rateLimiter     *ratelimit.Limiter
	resendLimiter   *ratelimit.Limiter
	// usernameLimiter throttles the availability probe on a budget of its own. The
	// shared limiter keys on the request path, so the probe would otherwise draw from
	// a credential-sized budget while a user is still typing.
	usernameLimiter *ratelimit.Limiter
	// cookies builds every session cookie this handler writes. It is never nil:
	// NewHandler installs one backed by default tenant policy, and
	// WithSessionPolicyResolver replaces it with one that reads live policy.
	cookies   *authcookie.Writer
	blocklist *tokenblocklist.Blocklist
}

// NewHandler constructs a new Auth Handler instance.
func NewHandler(service *Service, policyRepo *policy.Repository, rateLimiter *ratelimit.Limiter, resendLimiter ...*ratelimit.Limiter) *Handler {
	telemetry := NewTelemetryService(service.repo, service.config.EncryptionKey, policyRepo)
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

// WithUsernameLimiter sets the limiter guarding the username availability probe,
// and returns the handler for chaining.
//
// Left unset, the probe falls back to the shared credential limiter, which is the
// safe default rather than the intended one: a budget written for password attempts
// rejects a user still typing their handle. It is a separate method rather than a
// constructor parameter so the handler stays constructible in tests that have no
// limiter behind them.
func (h *Handler) WithUsernameLimiter(l *ratelimit.Limiter) *Handler {
	h.usernameLimiter = l
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

	// throttled builds a public chain that swaps the shared credential limiter for a
	// route-specific one. The publishable key middleware stays ahead of it, because
	// the limiter reads the tenant it namespaces buckets by out of what that
	// middleware resolved.
	throttled := func(limiter *ratelimit.Limiter, handler fiber.Handler) []fiber.Handler {
		if limiter == nil {
			return public(handler)
		}
		chain := []fiber.Handler{}
		if pkMiddleware != nil {
			chain = append(chain, pkMiddleware)
		}
		return append(chain, limiter.Middleware(), handler)
	}

	// Registration, password sign-in and email verification.
	//
	// Every client authentication route lives under /v1/client/auth/. The prefix
	// is the whole grouping rule: a reader looking for "how does one authenticate"
	// finds the complete set in one place, and a route that mutates credentials
	// cannot be mistaken for /v1/client/user profile management beside it.
	api.Post("/auth/signup", public(h.SignUp)...)
	api.Post("/auth/login", public(h.Login)...)
	api.Get("/auth/verify-email", public(h.VerifyEmail)...)
	api.Post("/auth/resend-verification", public(h.ResendVerification)...)

	// Username availability, on a budget of its own (see WithUsernameLimiter).
	//
	// GET rather than POST: it is a read, it is safe to repeat, and a sign-up form
	// calls it on every keystroke behind a debounce. The handle travels in the query
	// string, which is also why the response carries no more than the sign-up form
	// would reveal a moment later — a caller can already learn a handle is taken by
	// attempting to register it.
	api.Get("/auth/username-available", throttled(h.usernameLimiter, h.CheckUsername)...)

	// Passwordless magic link (FR-15). The emailed token is the credential.
	//
	// POST only. The emailed link opens the frontend, which posts the token here
	// with its own publishable key; a GET reachable by browser navigation would
	// answer a top-level request with an access token in the response body, where
	// it lands in history and in the Referer of every link on the page.
	api.Post("/auth/magic-link", public(h.SendMagicLink)...)
	api.Post("/auth/magic-link/verify", public(h.VerifyMagicLink)...)

	// Which second factors the account has enrolled (FR-4).
	//
	// Session-authenticated and read-only. It answers the same question activeFactors answers for
	// the login challenge, which is why it lives here and not beside the profile: a settings page
	// and a sign-in must agree on what the account can be challenged with, and two computations of
	// that would eventually disagree.
	api.Get("/auth/2fa/methods", protected(h.GetTwoFactorMethods)...)

	// TOTP second factor (FR-4). Verification is public because it also serves the login
	// challenge, where the caller holds an mfa_token rather than a session.
	api.Post("/auth/2fa/totp/enroll", protected(h.EnrollTOTP)...)
	api.Post("/auth/2fa/totp/confirm", protected(h.ConfirmTOTP)...)
	api.Post("/auth/2fa/totp/disable", protected(h.DisableTOTP)...)
	api.Post("/auth/2fa/totp/verify", public(h.VerifyTOTP)...)
	// Method-agnostic alias for the login challenge: a caller holding an mfa_token
	// posts the code here without needing to know which factor issued it.
	api.Post("/auth/2fa/verify", public(h.VerifyTOTP)...)

	// SMS OTP second factor (FR-4).
	api.Post("/auth/2fa/sms/enroll", protected(h.EnrollSMS)...)
	api.Post("/auth/2fa/sms/confirm", protected(h.ConfirmSMS)...)
	api.Delete("/auth/2fa/sms/disable", protected(h.DisableSMS)...)
	// Public for the same reason verification is: the login challenge's caller holds an mfa_token
	// and no session. Without this the challenge could advertise `sms` among its methods and never
	// satisfy it, since a code is only ever minted by a send.
	api.Post("/auth/2fa/sms/challenge", public(h.SendSMSChallenge)...)

	// Backup recovery codes (FR-4).
	api.Post("/auth/2fa/recovery-codes/regenerate", protected(h.RegenerateRecoveryCodes)...)
	api.Get("/auth/2fa/recovery-codes/status", protected(h.GetRecoveryCodesStatus)...)

	// WebAuthn passkeys (FR-4). Registration needs a session; login is authorized by mfa_token.
	api.Post("/auth/2fa/webauthn/register/begin", protected(h.BeginWebAuthnRegistration)...)
	api.Post("/auth/2fa/webauthn/register/finish", protected(h.FinishWebAuthnRegistration)...)
	api.Post("/auth/2fa/webauthn/login/begin", public(h.BeginWebAuthnLogin)...)
	api.Post("/auth/2fa/webauthn/login/finish", public(h.FinishWebAuthnLogin)...)
	api.Get("/auth/2fa/webauthn/credentials", protected(h.ListWebAuthnPasskeys)...)
	api.Delete("/auth/2fa/webauthn/credentials/:id", protected(h.DeleteWebAuthnPasskey)...)

	// Guardian roster management (FR-5). Accepting an invitation is public: the invitee is a
	// different person from the account holder and generally has no session here.
	api.Post("/account/guardians/invite", protected(h.InviteGuardians)...)
	api.Post("/account/guardians/accept", public(h.AcceptGuardianInvite)...)
	api.Get("/account/guardians", protected(h.ListGuardians)...)
	api.Delete("/account/guardians/:id", protected(h.RevokeGuardian)...)

	// Security questions (FR-5), the last-resort recovery factor. Enrolling one needs no second
	// party, unlike a guardian invitation, so the write routes take a step-up of their own.
	api.Get("/account/security-questions", protected(h.ListSecurityQuestions)...)
	api.Put("/account/security-questions", protected(h.SetSecurityQuestions)...)
	api.Delete("/account/security-questions", protected(h.DeleteSecurityQuestions)...)

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
	// TenantID and Environment are populated from the credential that
	// authenticated the request, not from the body. They are excluded from JSON so
	// a caller cannot name a tenant or reach live data with a test key.
	TenantID    string `json:"-"`
	Environment string `json:"-"`
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
	case errors.Is(err, ErrFactorUnavailable):
		return httperr.CodeValidationFailed, ErrFactorUnavailable.Error(), true
	case errors.Is(err, ErrPasskeyVerificationRoute):
		return httperr.CodeValidationFailed, ErrPasskeyVerificationRoute.Error(), true
	case errors.Is(err, ErrFactorsUnavailable):
		return httperr.CodeServiceUnavailable, ErrFactorsUnavailable.Error(), true
	case errors.Is(err, ErrTooManySMSRequests):
		return httperr.CodeRateLimited, ErrTooManySMSRequests.Error(), true
	case errors.Is(err, ErrSMSNotEnrolled):
		return httperr.CodeNotFound, ErrSMSNotEnrolled.Error(), true
	case errors.Is(err, ErrSMSDeliveryFailed):
		return httperr.CodeServiceUnavailable, ErrSMSDeliveryFailed.Error(), true
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
