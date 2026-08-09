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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
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
		guardianService: NewGuardianService(service.repo, policyRepo),
		recoveryService: NewRecoveryService(service.repo, telemetry, policyRepo),
		policyRepo:      policyRepo,
		rateLimiter:     rateLimiter,
		resendLimiter:   rLimiter,
	}
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
	clientAuth := middleware.RequireClientAuth(h.service.config.EncryptionKey)

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

// SendMagicLink handles requests to send a passwordless magic login link.
func (h *Handler) SendMagicLink(c *fiber.Ctx) error {
	var req SendMagicLinkDTO
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if tenantID, ok := c.Locals("tenant_id").(string); ok && tenantID != "" {
		req.TenantID = tenantID
	} else if req.TenantID == "" {
		req.TenantID = "tnt_default"
	}

	if env, ok := c.Locals("environment").(string); ok && env != "" {
		req.Environment = env
	} else if req.Environment == "" {
		req.Environment = "test"
	}

	if !isValidEmail(req.Email) {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "invalid email address format")
	}

	userAgent := c.Get("User-Agent", "unknown")
	ipAddress := c.IP()

	if err := h.service.SendMagicLink(c.UserContext(), req.TenantID, req.Environment, req.Email, req.Name, userAgent, ipAddress); err != nil {
		return httperr.SendInternal(c, "auth.send_magic_link", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "a magic login link has been sent to your email address",
	})
}

// VerifyMagicLink validates a magic login token, consumes it, marks email verified, and issues session tokens.
func (h *Handler) VerifyMagicLink(c *fiber.Ctx) error {
	var token string
	if c.Method() == fiber.MethodGet {
		token = c.Query("token")
	} else {
		var req VerifyMagicLinkDTO
		if err := c.BodyParser(&req); err == nil && req.Token != "" {
			token = req.Token
		} else {
			token = c.Query("token")
		}
	}

	if strings.TrimSpace(token) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "token query parameter or body field is required")
	}

	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, msgInvalidClientType)
	}

	userAgent := c.Get("User-Agent", "unknown")
	ipAddress := c.IP()

	u, accessToken, refreshToken, err := h.service.VerifyMagicLinkToken(c.UserContext(), token, userAgent, ipAddress)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeMagicLinkExpired, "invalid or expired magic link token")
	}

	var namePtr *string
	if u.Name != "" {
		namePtr = &u.Name
	}

	refreshTokenBody := ""
	if clientType == "native" || clientType == "mobile" {
		refreshTokenBody = refreshToken
	} else {
		cookie := new(fiber.Cookie)
		cookie.Name = "authn_refresh_token"
		cookie.Value = refreshToken
		cookie.Expires = time.Now().Add(30 * 24 * time.Hour)
		cookie.HTTPOnly = true
		cookie.Secure = h.service.config.CookieSecure()
		cookie.SameSite = "Lax"
		c.Cookie(cookie)
	}

	return c.Status(fiber.StatusOK).JSON(AuthResponse{
		User: UserDTO{
			ID:            u.ID,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          namePtr,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshTokenBody,
	})
}

// SignUp handles user registration requests.
func (h *Handler) SignUp(c *fiber.Ctx) error {
	var req SignUpRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if tID, ok := c.Locals("tenant_id").(string); ok && tID != "" {
		req.TenantID = tID
	} else if req.TenantID == "" {
		req.TenantID = "tnt_default"
	}

	if env, ok := c.Locals("environment").(string); ok && env != "" {
		req.Environment = env
	} else if req.Environment == "" {
		req.Environment = "test"
	}
	if req.Email == "" || req.Password == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "email and password are required")
	}
	if !isValidEmail(req.Email) {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "invalid email address format")
	}
	if len(req.Name) > 255 {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "name cannot exceed 255 characters")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, msgInvalidClientType)
	}

	// Validate tenant password policy (defaulting to 8-character NIST 800-63B baseline)
	var policyWarning *PolicyWarningDTO
	if h.policyRepo != nil {
		pol, err := h.policyRepo.GetPasswordPolicy(c.UserContext(), req.TenantID)
		if err != nil {
			pol = policy.DefaultPasswordPolicy()
		}
		missingCriteria := policy.ValidatePassword(pol, req.Password)
		if len(missingCriteria) > 0 {
			if pol.EnforcementMode == "require" {
				return sendWithDetails(c, fiber.StatusBadRequest, httperr.CodeValidationFailed,
					"password does not meet policy requirements",
					fiber.Map{"missing_criteria": missingCriteria})
			}
			policyWarning = &PolicyWarningDTO{
				MissingCriteria: missingCriteria,
			}
		}
	}

	u, accessToken, refreshToken, err := h.service.SignUpWithPassword(c.UserContext(), req.TenantID, req.Environment, req.Email, req.Password, req.Name, userAgent, ipAddress)
	if err != nil {
		if errors.Is(err, ErrUserAlreadyExists) {
			return httperr.Conflict(c, httperr.CodeAlreadyExists, ErrUserAlreadyExists.Error())
		}
		return httperr.SendInternal(c, "auth.signup", err)
	}

	// Check tenant security policy compliance (require_email_verification notice on signup)
	if h.policyRepo != nil {
		secPol, err := h.policyRepo.GetSecurityPolicy(c.UserContext(), req.TenantID)
		if err == nil && secPol.RequireEmailVerification && !u.EmailVerified {
			if policyWarning == nil {
				policyWarning = &PolicyWarningDTO{}
			}
			policyWarning.RequiresEmailVerification = true
		}
	}

	var namePtr *string
	if u.Name != "" {
		namePtr = &u.Name
	}

	refreshTokenBody := ""
	if clientType == "native" || clientType == "mobile" {
		refreshTokenBody = refreshToken
	} else {
		// Web clients receive refresh token strictly via HttpOnly cookie (XSS protection)
		c.Cookie(&fiber.Cookie{
			Name:     "authn_refresh_token",
			Value:    refreshToken,
			HTTPOnly: true,
			Secure:   h.service.config.CookieSecure(),
			SameSite: "Lax",
			Path:     "/v1/client",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(AuthResponse{
		User: UserDTO{
			ID:            u.ID,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          namePtr,
			Status:        string(u.Status),
			CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:   accessToken,
		RefreshToken:  refreshTokenBody,
		PolicyWarning: policyWarning,
	})
}

// Login handles password authentication requests.
func (h *Handler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if tID, ok := c.Locals("tenant_id").(string); ok && tID != "" {
		req.TenantID = tID
	} else if req.TenantID == "" {
		req.TenantID = "tnt_default"
	}

	if env, ok := c.Locals("environment").(string); ok && env != "" {
		req.Environment = env
	} else if req.Environment == "" {
		req.Environment = "test"
	}

	if req.Email == "" || req.Password == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "email and password are required")
	}
	if !isValidEmail(req.Email) {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "invalid email address format")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, msgInvalidClientType)
	}

	u, accessToken, refreshToken, err := h.service.ValidatePasswordCredentials(c.UserContext(), req.TenantID, req.Environment, req.Email, req.Password, userAgent, ipAddress)
	if err != nil {
		if errors.Is(err, Err2FARequired) {
			var namePtr *string
			if u != nil && u.Name != "" {
				namePtr = &u.Name
			}
			// Single source of truth: extract allowed 2FA methods directly from signed MFA token claims
			methods := []string{"totp"}
			if mfaClaims, cErr := jwtpkg.VerifyMFAChallengeToken(accessToken, h.service.config.EncryptionKey); cErr == nil && len(mfaClaims.Methods) > 0 {
				methods = mfaClaims.Methods
			}
			return c.Status(fiber.StatusOK).JSON(AuthResponse{
				User: UserDTO{
					ID:            u.ID,
					Email:         u.Email,
					EmailVerified: u.EmailVerified,
					Name:          namePtr,
					Status:        string(u.Status),
					CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
				},
				MFARequired: true,
				MFAToken:    accessToken,
				Methods:     methods,
			})
		}
		// Every non-2FA failure here already answered 401, including wrapped
		// internal errors. Keep that status, but never echo the error: the
		// account-status and token-issuance messages behind it are internal.
		return sendServiceError(c, "auth.login", fiber.StatusUnauthorized, err,
			httperr.CodeInvalidCredentials, ErrInvalidCredentials.Error())
	}

	// Check password policy compliance & force upgrade flags on login
	var policyWarning *PolicyWarningDTO
	if h.policyRepo != nil {
		pol, err := h.policyRepo.GetPasswordPolicy(c.Context(), req.TenantID)
		if err == nil {
			missingCriteria := policy.ValidatePassword(pol, req.Password)
			if len(missingCriteria) > 0 && pol.ForceUpgradeOnSignin {
				policyWarning = &PolicyWarningDTO{
					RequiresPasswordUpgrade: true,
					MissingCriteria:         missingCriteria,
				}
			}
		}

		// Check tenant security policy compliance (require_email_verification enforcement)
		secPol, err := h.policyRepo.GetSecurityPolicy(c.UserContext(), req.TenantID)
		if err == nil && secPol.RequireEmailVerification && !u.EmailVerified {
			if secPol.EmailVerificationMode == "hard" {
				return sendWithDetails(c, fiber.StatusForbidden, httperr.CodeEmailVerificationRequired,
					"email verification is required before signing in",
					fiber.Map{"email_verified": false})
			}
			if policyWarning == nil {
				policyWarning = &PolicyWarningDTO{}
			}
			policyWarning.RequiresEmailVerification = true
		}
	}

	var namePtr *string
	if u.Name != "" {
		namePtr = &u.Name
	}

	refreshTokenBody := ""
	if clientType == "native" || clientType == "mobile" {
		refreshTokenBody = refreshToken
	} else {
		// Web clients receive refresh token strictly via HttpOnly cookie (XSS protection)
		c.Cookie(&fiber.Cookie{
			Name:     "authn_refresh_token",
			Value:    refreshToken,
			HTTPOnly: true,
			Secure:   h.service.config.CookieSecure(),
			SameSite: "Lax",
			Path:     "/v1/client",
		})
	}

	return c.Status(fiber.StatusOK).JSON(AuthResponse{
		User: UserDTO{
			ID:            u.ID,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          namePtr,
			Status:        string(u.Status),
			CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:   accessToken,
		RefreshToken:  refreshTokenBody,
		PolicyWarning: policyWarning,
	})
}

// VerifyEmail handles email verification link requests (GET /v1/client/verify-email?token=...).
func (h *Handler) VerifyEmail(c *fiber.Ctx) error {
	token := strings.TrimSpace(c.Query("token"))
	if token == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "verification token query parameter is required")
	}

	u, err := h.service.VerifyEmailToken(c.UserContext(), token)
	if err != nil {
		return sendServiceError(c, "auth.verify_email", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, "invalid or expired verification token")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":        "email successfully verified",
		"email":          u.Email,
		"email_verified": true,
	})
}

// ResendVerification handles resending verification emails (POST /v1/client/resend-verification).
func (h *Handler) ResendVerification(c *fiber.Ctx) error {
	var req struct {
		TenantID    string `json:"tenant_id"`
		Environment string `json:"environment"`
		Email       string `json:"email"`
	}

	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if tID, ok := c.Locals("tenant_id").(string); ok && tID != "" {
		req.TenantID = tID
	} else if req.TenantID == "" {
		req.TenantID = "tnt_default"
	}

	if env, ok := c.Locals("environment").(string); ok && env != "" {
		req.Environment = env
	} else if req.Environment == "" {
		req.Environment = "test"
	}

	if !isValidEmail(req.Email) {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "invalid email address format")
	}

	if h.resendLimiter != nil {
		emailClean := strings.ToLower(strings.TrimSpace(req.Email))
		hStr := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", req.TenantID, emailClean)))
		emailHash := hex.EncodeToString(hStr[:])[:16]
		key := fmt.Sprintf("%s:resend_email:%s", req.TenantID, emailHash)

		allowed, retryAfter, err := h.resendLimiter.Check(c.UserContext(), key)
		if err != nil {
			if errors.Is(err, ratelimit.ErrRedisUnavailable) {
				return httperr.Send(c, fiber.StatusServiceUnavailable, httperr.CodeServiceUnavailable,
					"rate limit service unavailable")
			}
			return httperr.SendInternal(c, "auth.resend_verification.ratelimit", err)
		}
		if !allowed {
			if retryAfter > 0 {
				c.Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			}
			return sendWithDetails(c, fiber.StatusTooManyRequests, httperr.CodeRateLimited,
				"too many verification email requests for this address, please try again later",
				fiber.Map{"retry_after_seconds": int(retryAfter.Seconds())})
		}
	}

	if err := h.service.ResendVerificationEmail(c.UserContext(), req.TenantID, req.Environment, req.Email); err != nil {
		return httperr.SendInternal(c, "auth.resend_verification", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "if an account exists with this email address, a verification link has been sent",
	})
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

// TOTPConfirmRequest payload for confirming TOTP enrollment.
type TOTPConfirmRequest struct {
	Code string `json:"code" example:"123456"`
}

// TOTPVerifyRequest payload for verifying a TOTP code during session or login.
type TOTPVerifyRequest struct {
	Code     string `json:"code" example:"123456"`
	MFAToken string `json:"mfa_token,omitempty"`
	Method   string `json:"method,omitempty"`
}

// TOTPDisableRequest payload for removing TOTP 2FA.
type TOTPDisableRequest struct {
	Password string `json:"password" example:"SuperSecret123!"`
}

// extractBearerToken resolves the caller's access token from the authn_access_token cookie, the
// access_token cookie, or an Authorization: Bearer header, in that order.
//
// Cookies take precedence over the header, matching middleware.RequireClientAuth. The two must
// agree: a route whose token source differs from the one the middleware reads would authenticate
// a different caller than the middleware authorized.
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
//
// It is only meaningful on a route registered with protected(); on a public route it returns "",
// which every caller must treat as a programming error rather than as an anonymous user.
func getUserID(c *fiber.Ctx) string {
	if val, ok := c.Locals("userID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("user_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// EnrollTOTP handles POST /v1/client/2fa/totp/enroll.
// Generates a new TOTP secret for the authenticated user and stores it in pending state (is_enabled = false).
func (h *Handler) EnrollTOTP(c *fiber.Ctx) error {
	userID := getUserID(c)

	result, err := h.service.EnrollTOTP(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.totp.enroll", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"secret": result.Secret,
		"uri":    result.URI,
	})
}

// ConfirmTOTP handles POST /v1/client/2fa/totp/confirm.
// Validates a 6-digit TOTP code against the pending secret and enables 2FA (is_enabled = true).
func (h *Handler) ConfirmTOTP(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req TOTPConfirmRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "code is required")
	}

	res, err := h.service.ConfirmTOTP(c.UserContext(), userID, strings.TrimSpace(req.Code))
	if err != nil {
		return sendServiceError(c, "auth.totp.confirm", fiber.StatusBadRequest, err,
			httperr.CodeInvalidMFACode, "unable to confirm TOTP enrollment with the supplied code")
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// VerifyTOTP handles POST /v1/client/2fa/totp/verify and POST /v1/client/auth/2fa/verify.
// Validates a 6-digit TOTP code during login challenge or within an authenticated session.
func (h *Handler) VerifyTOTP(c *fiber.Ctx) error {
	var req TOTPVerifyRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "code is required")
	}

	mfaToken := req.MFAToken

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, msgInvalidClientType)
	}

	// 1. If MFA challenge token is provided (login 2FA verification flow)
	if mfaToken != "" {
		u, accessToken, refreshToken, err := h.service.VerifyTOTPChallenge(c.UserContext(), mfaToken, strings.TrimSpace(req.Code), req.Method, userAgent, ipAddress)
		if err != nil {
			return sendServiceError(c, "auth.2fa.verify_challenge", fiber.StatusBadRequest, err,
				httperr.CodeInvalidMFACode, "two-factor verification failed")
		}

		var namePtr *string
		if u.Name != "" {
			namePtr = &u.Name
		}

		refreshTokenBody := ""
		if clientType == "native" || clientType == "mobile" {
			refreshTokenBody = refreshToken
		} else {
			c.Cookie(&fiber.Cookie{
				Name:     "authn_refresh_token",
				Value:    refreshToken,
				HTTPOnly: true,
				Secure:   h.service.config.CookieSecure(),
				SameSite: "Lax",
				Path:     "/v1/client",
			})
		}

		return c.Status(fiber.StatusOK).JSON(AuthResponse{
			User: UserDTO{
				ID:            u.ID,
				Email:         u.Email,
				EmailVerified: u.EmailVerified,
				Name:          namePtr,
				Status:        string(u.Status),
				CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
			},
			AccessToken:  accessToken,
			RefreshToken: refreshTokenBody,
		})
	}

	// 2. Direct verification inside an already-authenticated session.
	//
	// This route is public because branch 1 above serves the login challenge, where the caller
	// holds an mfa_token and no session. The bearer path therefore has to authenticate itself.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: session token or two_factor_token required")
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.EncryptionKey)
	if err != nil {
		// The parse error names why the token failed (expired, bad signature, wrong algorithm),
		// which an unauthenticated caller must not learn.
		return httperr.Unauthorized(c, httperr.CodeSessionExpired, "unauthorized session: invalid or expired session token")
	}

	if err := h.service.Verify2FACode(c.UserContext(), claims.Sub, strings.TrimSpace(req.Code), req.Method); err != nil {
		return sendServiceError(c, "auth.2fa.verify", fiber.StatusBadRequest, err,
			httperr.CodeInvalidMFACode, "two-factor verification failed")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"valid": true,
	})
}

// DisableTOTP handles POST /v1/client/2fa/totp/disable.
// Re-verifies current password using Argon2id, removes TOTP 2FA, and revokes all active user sessions for security.
func (h *Handler) DisableTOTP(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req TOTPDisableRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "password is required for 2FA step-up confirmation")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	if err := h.service.DisableTOTP(c.UserContext(), userID, req.Password, userAgent, ipAddress); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, "invalid password confirmation")
		}
		return sendServiceError(c, "auth.totp.disable", fiber.StatusBadRequest, err,
			httperr.CodeForbidden, "unable to disable TOTP 2FA")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "2FA TOTP disabled. All active sessions have been revoked for security.",
	})
}

// RecoveryCodesRegenerateRequest payload for regenerating backup recovery codes.
type RecoveryCodesRegenerateRequest struct {
	Password string `json:"password" example:"SuperSecret123!"`
}

// RegenerateRecoveryCodes handles POST /v1/client/2fa/recovery-codes/regenerate.
// Requires Argon2id password step-up, invalidates all old recovery codes, and issues 16 fresh codes.
func (h *Handler) RegenerateRecoveryCodes(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req RecoveryCodesRegenerateRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "password is required for recovery codes regeneration step-up")
	}

	codes, err := h.service.RegenerateRecoveryCodes(c.UserContext(), userID, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, "invalid password confirmation")
		}
		return sendServiceError(c, "auth.recovery_codes.regenerate", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to regenerate recovery codes")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":        "recovery codes successfully regenerated",
		"recovery_codes": codes,
	})
}

// GetRecoveryCodesStatus handles GET /v1/client/2fa/recovery-codes/status.
// Returns remaining unused count of recovery codes for the authenticated user without exposing code values.
func (h *Handler) GetRecoveryCodesStatus(c *fiber.Ctx) error {
	userID := getUserID(c)

	res, err := h.service.GetRecoveryCodesStatus(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.recovery_codes.status", err)
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// WebAuthnRegisterFinishRequest payload for completing passkey registration.
type WebAuthnRegisterFinishRequest struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name,omitempty"`
}

// WebAuthnLoginBeginRequest payload for starting passkey login challenge flow.
type WebAuthnLoginBeginRequest struct {
	MFAToken string `json:"mfa_token"`
}

// WebAuthnLoginFinishRequest payload for completing passkey login challenge flow.
type WebAuthnLoginFinishRequest struct {
	MFAToken  string `json:"mfa_token"`
	SessionID string `json:"session_id"`
}

// PasskeyDeleteRequest payload for removing a passkey.
type PasskeyDeleteRequest struct {
	Password string `json:"password,omitempty"`
}

// BeginWebAuthnRegistration handles POST /v1/client/2fa/webauthn/register/begin.
func (h *Handler) BeginWebAuthnRegistration(c *fiber.Ctx) error {
	userID := getUserID(c)

	options, sessionID, err := h.service.BeginWebAuthnRegistration(c.UserContext(), userID)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.register_begin", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to begin passkey registration")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"options":    options,
		"session_id": sessionID,
	})
}

// FinishWebAuthnRegistration handles POST /v1/client/2fa/webauthn/register/finish.
func (h *Handler) FinishWebAuthnRegistration(c *fiber.Ctx) error {
	userID := getUserID(c)

	sessionID := c.Query("session_id")
	passkeyName := c.Query("name")
	if sessionID == "" {
		var req WebAuthnRegisterFinishRequest
		_ = c.BodyParser(&req)
		sessionID = req.SessionID
		if req.Name != "" {
			passkeyName = req.Name
		}
	}
	if sessionID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "session_id is required")
	}

	httpReq, err := http.NewRequestWithContext(c.UserContext(), c.Method(), c.OriginalURL(), bytes.NewReader(c.Body()))
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeInvalidRequestBody, "invalid http request format")
	}
	for k, v := range c.GetReqHeaders() {
		if len(v) > 0 {
			httpReq.Header.Set(k, v[0])
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := h.service.FinishWebAuthnRegistration(c.UserContext(), userID, sessionID, httpReq, passkeyName)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.register_finish", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to complete passkey registration")
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// BeginWebAuthnLogin handles POST /v1/client/2fa/webauthn/login/begin.
func (h *Handler) BeginWebAuthnLogin(c *fiber.Ctx) error {
	var req WebAuthnLoginBeginRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.MFAToken) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "mfa_token is required")
	}

	options, sessionID, userID, err := h.service.BeginWebAuthnLogin(c.UserContext(), req.MFAToken)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.login_begin", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to begin passkey login")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"options":    options,
		"session_id": sessionID,
		"user_id":    userID,
	})
}

// FinishWebAuthnLogin handles POST /v1/client/2fa/webauthn/login/finish.
func (h *Handler) FinishWebAuthnLogin(c *fiber.Ctx) error {
	mfaToken := c.Query("mfa_token")
	sessionID := c.Query("session_id")
	if mfaToken == "" || sessionID == "" {
		var req WebAuthnLoginFinishRequest
		_ = c.BodyParser(&req)
		if mfaToken == "" {
			mfaToken = req.MFAToken
		}
		if sessionID == "" {
			sessionID = req.SessionID
		}
	}
	if mfaToken == "" || sessionID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "mfa_token and session_id are required")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, msgInvalidClientType)
	}

	httpReq, err := http.NewRequestWithContext(c.UserContext(), c.Method(), c.OriginalURL(), bytes.NewReader(c.Body()))
	if err != nil {
		return httperr.BadRequest(c, httperr.CodeInvalidRequestBody, "invalid http request format")
	}
	for k, v := range c.GetReqHeaders() {
		if len(v) > 0 {
			httpReq.Header.Set(k, v[0])
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	u, accessToken, refreshToken, err := h.service.FinishWebAuthnLogin(c.UserContext(), mfaToken, sessionID, httpReq, userAgent, ipAddress)
	if err != nil {
		return sendServiceError(c, "auth.webauthn.login_finish", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to complete passkey login")
	}

	var namePtr *string
	if u.Name != "" {
		namePtr = &u.Name
	}

	refreshTokenBody := ""
	if clientType == "native" || clientType == "mobile" {
		refreshTokenBody = refreshToken
	} else {
		c.Cookie(&fiber.Cookie{
			Name:     "authn_refresh_token",
			Value:    refreshToken,
			HTTPOnly: true,
			Secure:   h.service.config.CookieSecure(),
			SameSite: "Lax",
			Path:     "/v1/client",
		})
	}

	return c.Status(fiber.StatusOK).JSON(AuthResponse{
		User: UserDTO{
			ID:            u.ID,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          namePtr,
			Status:        string(u.Status),
			CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:  accessToken,
		RefreshToken: refreshTokenBody,
	})
}

// ListWebAuthnPasskeys handles GET /v1/client/2fa/webauthn/credentials.
func (h *Handler) ListWebAuthnPasskeys(c *fiber.Ctx) error {
	userID := getUserID(c)

	credentials, err := h.service.ListWebAuthnPasskeys(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.webauthn.list_passkeys", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"credentials": credentials,
	})
}

// DeleteWebAuthnPasskey handles DELETE /v1/client/2fa/webauthn/credentials/:id.
func (h *Handler) DeleteWebAuthnPasskey(c *fiber.Ctx) error {
	userID := getUserID(c)

	passkeyID := c.Params("id")
	if passkeyID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "passkey id is required")
	}

	var req PasskeyDeleteRequest
	_ = c.BodyParser(&req)

	if err := h.service.DeleteWebAuthnPasskey(c.UserContext(), userID, passkeyID, req.Password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, "invalid password step-up confirmation required to delete your last remaining 2FA method")
		}
		return sendServiceError(c, "auth.webauthn.delete_passkey", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to delete passkey")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "passkey successfully deleted",
	})
}

// SMSEnrollRequest payload for initiating SMS 2FA.
type SMSEnrollRequest struct {
	PhoneNumber string `json:"phone_number" example:"+12025550199"`
}

// SMSConfirmRequest payload for confirming SMS 2FA enrollment.
type SMSConfirmRequest struct {
	Code string `json:"code" example:"482910"`
}

// SMSDisableRequest payload for removing SMS 2FA.
type SMSDisableRequest struct {
	Password string `json:"password" example:"SuperSecret123!"`
}

// EnrollSMS handles POST /v1/client/2fa/sms/enroll.
func (h *Handler) EnrollSMS(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req SMSEnrollRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.PhoneNumber) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "phone_number is required")
	}

	if err := h.service.BeginSMSEnrollment(c.UserContext(), userID, strings.TrimSpace(req.PhoneNumber)); err != nil {
		return sendServiceError(c, "auth.sms.enroll", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to begin SMS enrollment")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":            "OTP verification code sent via SMS",
		"expires_in_seconds": 300,
	})
}

// ConfirmSMS handles POST /v1/client/2fa/sms/confirm.
func (h *Handler) ConfirmSMS(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req SMSConfirmRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "code is required")
	}

	res, err := h.service.ConfirmSMSEnrollment(c.UserContext(), userID, strings.TrimSpace(req.Code))
	if err != nil {
		return sendServiceError(c, "auth.sms.confirm", fiber.StatusBadRequest, err,
			httperr.CodeInvalidMFACode, "unable to confirm SMS enrollment with the supplied code")
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// DisableSMS handles DELETE /v1/client/2fa/sms/disable.
func (h *Handler) DisableSMS(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req SMSDisableRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "password is required")
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	if err := h.service.DisableSMS2FA(c.UserContext(), userID, req.Password, userAgent, ipAddress); err != nil {
		return sendServiceError(c, "auth.sms.disable", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to disable SMS 2FA")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "SMS 2FA disabled successfully",
	})
}

// InviteGuardians handles POST /v1/client/account/guardians/invite. Requires step-up re-auth / fresh session.
func (h *Handler) InviteGuardians(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req struct {
		Guardians []InviteGuardianInput `json:"guardians"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.Guardians) == 0 {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"Invalid payload: must provide 1 to 5 guardian email and name objects")
	}

	baseURL := fmt.Sprintf("%s://%s", c.Protocol(), c.Hostname())
	res, err := h.guardianService.InviteGuardians(c.Context(), userID, req.Guardians, baseURL)
	if err != nil {
		return sendServiceError(c, "auth.guardians.invite", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to invite the requested guardians")
	}

	return c.Status(fiber.StatusCreated).JSON(res)
}

// AcceptGuardianInvite handles POST /v1/client/account/guardians/accept.
func (h *Handler) AcceptGuardianInvite(c *fiber.Ctx) error {
	var req struct {
		ContactID string `json:"contact_id"`
		Token     string `json:"token"`
	}
	if err := c.BodyParser(&req); err != nil || req.ContactID == "" || req.Token == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "contact_id and token are required")
	}

	if err := h.guardianService.AcceptGuardianInvite(c.Context(), req.ContactID, req.Token); err != nil {
		return sendServiceError(c, "auth.guardians.accept", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, "invalid or expired guardian invitation")
	}

	return c.JSON(fiber.Map{
		"message": "Guardian invitation accepted successfully",
	})
}

// ListGuardians handles GET /v1/client/account/guardians.
func (h *Handler) ListGuardians(c *fiber.Ctx) error {
	userID := getUserID(c)

	dtos, err := h.guardianService.ListGuardians(c.Context(), userID)
	if err != nil {
		return httperr.SendInternal(c, "auth.guardians.list", err)
	}

	return c.JSON(fiber.Map{
		"guardians": dtos,
	})
}

// RevokeGuardian handles DELETE /v1/client/account/guardians/:id.
func (h *Handler) RevokeGuardian(c *fiber.Ctx) error {
	userID := getUserID(c)

	contactID := c.Params("id")
	if contactID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "Guardian contact ID is required")
	}

	if err := h.guardianService.RevokeGuardian(c.Context(), userID, contactID); err != nil {
		return sendServiceError(c, "auth.guardians.revoke", fiber.StatusBadRequest, err,
			httperr.CodeValidationFailed, "unable to revoke this guardian")
	}

	return c.JSON(fiber.Map{
		"message": "Guardian revoked successfully. Remaining guardians re-keyed with new Shamir shares.",
	})
}

// InitiateRecovery handles POST /v1/client/auth/recovery/initiate (Unauthenticated).
func (h *Handler) InitiateRecovery(c *fiber.Ctx) error {
	var req struct {
		TenantID    string `json:"tenant_id"`
		Environment string `json:"environment"`
		Email       string `json:"email"`
	}

	if err := c.BodyParser(&req); err != nil || req.Email == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "email address is required")
	}

	tenantID := req.TenantID
	if tenantID == "" {
		if t, ok := c.Locals("tenant_id").(string); ok && t != "" {
			tenantID = t
		} else {
			tenantID = "tnt_default"
		}
	}
	env := req.Environment
	if env == "" {
		env = "test"
	}

	deviceCookie := c.Cookies("authn_td_token")
	input := InitiateRecoveryInput{
		TenantID:     tenantID,
		Environment:  env,
		Email:        req.Email,
		IPAddress:    c.IP(),
		UserAgent:    c.Get("User-Agent"),
		AcceptLang:   c.Get("Accept-Language"),
		DeviceCookie: deviceCookie,
	}

	res, err := h.recoveryService.InitiateRecovery(c.Context(), input)
	// These two branches previously returned an inverted envelope — the machine
	// code in `error` and the prose in `message` — which is what forced the SDK
	// to substring-match across both fields. The prose and the machine code keep
	// their existing values; only the fields they live in are swapped back.
	if errors.Is(err, ErrNoRecoveryMethodsAvailable) {
		return httperr.Send(c, fiber.StatusBadRequest, httperr.Code("no_recovery_methods_available"),
			"No account recovery methods are configured for this account. Please contact system support for administrative assistance.")
	}
	if errors.Is(err, ErrOriginBlacklisted) {
		return httperr.Send(c, fiber.StatusForbidden, httperr.Code("origin_blacklisted"),
			"origin IP, subnet, or device fingerprint is temporarily blacklisted following a security cancellation")
	}
	if err != nil {
		return httperr.SendInternal(c, "auth.recovery.initiate", err)
	}

	// H3: never expose the cancellation token to the party that initiated recovery.
	// The token is the owner's veto against an unwanted takeover; it must reach the
	// owner out-of-band (their alert email), not the caller of this endpoint — which
	// may be the attacker. The field stays on the struct (omitempty) for internal use
	// and the signed-link cancel flow; we blank it here so it is omitted from the body.
	res.CancellationToken = ""

	return c.Status(fiber.StatusOK).JSON(res)
}

// SubmitGuardianProof handles POST /v1/client/auth/recovery/proof/guardian.
func (h *Handler) SubmitGuardianProof(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string `json:"recovery_request_id"`
		SharePayload      string `json:"share_payload"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" || req.SharePayload == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id and share_payload are required")
	}

	thresholdReached, err := h.recoveryService.SubmitGuardianShareProof(c.Context(), req.RecoveryRequestID, req.SharePayload)
	if err != nil {
		return sendServiceError(c, "auth.recovery.proof_guardian", fiber.StatusBadRequest, err,
			httperr.CodeInvalidCredentials, ErrInvalidProof.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"threshold_reached": thresholdReached,
		"status":            map[bool]string{true: "proof_verified", false: "awaiting_more_shares"}[thresholdReached],
	})
}

// SubmitOldPasswordProof handles POST /v1/client/auth/recovery/proof/old-password.
func (h *Handler) SubmitOldPasswordProof(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string `json:"recovery_request_id"`
		Password          string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" || req.Password == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id and password are required")
	}

	if err := h.recoveryService.SubmitOldPasswordProof(c.Context(), req.RecoveryRequestID, req.Password); err != nil {
		return sendServiceError(c, "auth.recovery.proof_old_password", fiber.StatusBadRequest, err,
			httperr.CodeInvalidCredentials, ErrInvalidProof.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "proof_verified",
		"message": "Old password verified successfully",
	})
}

// SubmitSecurityQuestionsProof handles POST /v1/client/auth/recovery/proof/security-questions.
func (h *Handler) SubmitSecurityQuestionsProof(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string            `json:"recovery_request_id"`
		Answers           map[string]string `json:"answers"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id is required")
	}

	if err := h.recoveryService.SubmitSecurityQuestionsProof(c.Context(), req.RecoveryRequestID, req.Answers); err != nil {
		return sendServiceError(c, "auth.recovery.proof_security_questions", fiber.StatusBadRequest, err,
			httperr.CodeInvalidCredentials, ErrInvalidProof.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "proof_verified",
		"message": "Security questions verified successfully",
	})
}

// ClaimAccount handles POST /v1/client/auth/recovery/claim.
func (h *Handler) ClaimAccount(c *fiber.Ctx) error {
	var req ClaimAccountInput
	if err := c.BodyParser(&req); err != nil || req.RequestID == "" || req.ClaimToken == "" || req.NewPassword == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "request_id, claim_token, and new_password are required")
	}

	req.IPAddress = c.IP()
	req.UserAgent = c.Get("User-Agent")
	req.AcceptLang = c.Get("Accept-Language")

	res, err := h.recoveryService.ClaimAccount(c.Context(), req)
	if err != nil {
		return sendServiceError(c, "auth.recovery.claim", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, "invalid or expired account claim request")
	}

	if res.DeviceCookie != "" {
		c.Cookie(&fiber.Cookie{
			Name:     "authn_td_token",
			Value:    res.DeviceCookie,
			Expires:  time.Now().Add(90 * 24 * time.Hour),
			HTTPOnly: true,
			Secure:   h.service.config.CookieSecure(),
			SameSite: "Lax",
		})
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// CancelRecoveryAuth handles POST /v1/client/auth/recovery/cancel (Authenticated Session).
func (h *Handler) CancelRecoveryAuth(c *fiber.Ctx) error {
	var req struct {
		RecoveryRequestID string `json:"recovery_request_id"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "recovery_request_id is required")
	}

	// This is the one authenticated route in this file that verifies its own bearer token rather
	// than being registered with protected(). Cancellation must spare the session issuing it, so
	// the handler needs the session ID from the `sid` claim, and RequireClientAuth publishes only
	// the user, tenant and environment. Verifying here keeps that claim reachable.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: session token required")
	}
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.EncryptionKey)
	if err != nil {
		// The parse error names why the token failed (expired, bad signature, wrong algorithm),
		// which an unauthenticated caller must not learn.
		return httperr.Unauthorized(c, httperr.CodeSessionExpired, "unauthorized session: invalid or expired session token")
	}
	userID := claims.Sub
	sessionID := claims.SessionID

	if err := h.recoveryService.CancelRecoveryRequestByAuthenticatedSession(c.Context(), userID, req.RecoveryRequestID, sessionID); err != nil {
		return sendServiceError(c, "auth.recovery.cancel_authenticated", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, ErrInvalidCancellationPoint.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "cancelled",
		"message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review.",
	})
}

// CancelRecoveryToken handles POST /v1/client/auth/recovery/cancel/token (Public Unauthenticated Signed Link).
func (h *Handler) CancelRecoveryToken(c *fiber.Ctx) error {
	var req struct {
		CancellationToken string `json:"cancellation_token"`
	}

	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.CancellationToken) == "" {
		// Fallback to query param token if body is empty
		req.CancellationToken = c.Query("cancellation_token")
	}

	if strings.TrimSpace(req.CancellationToken) == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "cancellation_token is required")
	}

	if err := h.recoveryService.CancelRecoveryRequestBySignedToken(c.Context(), req.CancellationToken); err != nil {
		return sendServiceError(c, "auth.recovery.cancel_token", fiber.StatusBadRequest, err,
			httperr.CodeInvalidToken, ErrInvalidCancellationPoint.Error())
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "cancelled",
		"message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review.",
	})
}
