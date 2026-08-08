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
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
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
	RequiresPasswordUpgrade  bool     `json:"requires_password_upgrade,omitempty"`
	RequiresEmailVerification bool     `json:"requires_email_verification,omitempty"`
	MissingCriteria          []string `json:"missing_criteria,omitempty"`
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

// RegisterRoutes attaches authentication endpoints to the Fiber app with rate limiting protection.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware fiber.Handler) {
	api := app.Group("/v1/client")
	var mws []fiber.Handler
	if pkMiddleware != nil {
		mws = append(mws, pkMiddleware)
	}
	if h.rateLimiter != nil {
		mws = append(mws, h.rateLimiter.Middleware())
	}

	signupHandlers := append(append([]fiber.Handler{}, mws...), h.SignUp)
	loginHandlers := append(append([]fiber.Handler{}, mws...), h.Login)
	verifyHandlers := append(append([]fiber.Handler{}, mws...), h.VerifyEmail)
	resendHandlers := append(append([]fiber.Handler{}, mws...), h.ResendVerification)
	magicLinkSendHandlers := append(append([]fiber.Handler{}, mws...), h.SendMagicLink)
	magicLinkVerifyHandlers := append(append([]fiber.Handler{}, mws...), h.VerifyMagicLink)
	totpEnrollHandlers := append(append([]fiber.Handler{}, mws...), h.EnrollTOTP)
	totpConfirmHandlers := append(append([]fiber.Handler{}, mws...), h.ConfirmTOTP)
	totpVerifyHandlers := append(append([]fiber.Handler{}, mws...), h.VerifyTOTP)
	totpDisableHandlers := append(append([]fiber.Handler{}, mws...), h.DisableTOTP)
	recRegenHandlers := append(append([]fiber.Handler{}, mws...), h.RegenerateRecoveryCodes)
	recStatusHandlers := append(append([]fiber.Handler{}, mws...), h.GetRecoveryCodesStatus)

	waRegBeginHandlers := append(append([]fiber.Handler{}, mws...), h.BeginWebAuthnRegistration)
	waRegFinishHandlers := append(append([]fiber.Handler{}, mws...), h.FinishWebAuthnRegistration)
	waLogBeginHandlers := append(append([]fiber.Handler{}, mws...), h.BeginWebAuthnLogin)
	waLogFinishHandlers := append(append([]fiber.Handler{}, mws...), h.FinishWebAuthnLogin)
	waListHandlers := append(append([]fiber.Handler{}, mws...), h.ListWebAuthnPasskeys)
	waDeleteHandlers := append(append([]fiber.Handler{}, mws...), h.DeleteWebAuthnPasskey)

	smsEnrollHandlers := append(append([]fiber.Handler{}, mws...), h.EnrollSMS)
	smsConfirmHandlers := append(append([]fiber.Handler{}, mws...), h.ConfirmSMS)
	smsDisableHandlers := append(append([]fiber.Handler{}, mws...), h.DisableSMS)

	api.Post("/signup", signupHandlers...)
	api.Post("/login", loginHandlers...)
	api.Get("/verify-email", verifyHandlers...)
	api.Post("/resend-verification", resendHandlers...)

	// Passwordless Magic Link routes (FR-15)
	api.Post("/auth/magic-link", magicLinkSendHandlers...)
	api.Get("/auth/magic-link/verify", magicLinkVerifyHandlers...)
	api.Post("/auth/magic-link/verify", magicLinkVerifyHandlers...)

	// 2FA TOTP & Recovery Code routes (FR-4)
	api.Post("/2fa/totp/enroll", totpEnrollHandlers...)
	api.Post("/2fa/totp/confirm", totpConfirmHandlers...)
	api.Post("/2fa/totp/verify", totpVerifyHandlers...)
	api.Post("/2fa/totp/disable", totpDisableHandlers...)
	api.Post("/auth/2fa/verify", totpVerifyHandlers...)

	// SMS OTP 2FA routes (FR-4)
	api.Post("/2fa/sms/enroll", smsEnrollHandlers...)
	api.Post("/2fa/sms/confirm", smsConfirmHandlers...)
	api.Delete("/2fa/sms/disable", smsDisableHandlers...)

	// Backup Recovery Code routes (FR-4)
	api.Post("/2fa/recovery-codes/regenerate", recRegenHandlers...)
	api.Get("/2fa/recovery-codes/status", recStatusHandlers...)

	// WebAuthn / Passkeys (FIDO2) routes (FR-4)
	api.Post("/2fa/webauthn/register/begin", waRegBeginHandlers...)
	api.Post("/2fa/webauthn/register/finish", waRegFinishHandlers...)
	api.Post("/2fa/webauthn/login/begin", waLogBeginHandlers...)
	api.Post("/2fa/webauthn/login/finish", waLogFinishHandlers...)
	api.Get("/2fa/webauthn/credentials", waListHandlers...)
	api.Delete("/2fa/webauthn/credentials/:id", waDeleteHandlers...)

	// Guardian Recovery routes (FR-5)
	gdnInviteHandlers := append(append([]fiber.Handler{}, mws...), h.InviteGuardians)
	gdnAcceptHandlers := append(append([]fiber.Handler{}, mws...), h.AcceptGuardianInvite)
	gdnListHandlers := append(append([]fiber.Handler{}, mws...), h.ListGuardians)
	gdnRevokeHandlers := append(append([]fiber.Handler{}, mws...), h.RevokeGuardian)
	recInitiateHandlers := append(append([]fiber.Handler{}, mws...), h.InitiateRecovery)
	recGuardianProofHandlers := append(append([]fiber.Handler{}, mws...), h.SubmitGuardianProof)
	recOldPassProofHandlers := append(append([]fiber.Handler{}, mws...), h.SubmitOldPasswordProof)
	recSecQuestProofHandlers := append(append([]fiber.Handler{}, mws...), h.SubmitSecurityQuestionsProof)
	recClaimHandlers := append(append([]fiber.Handler{}, mws...), h.ClaimAccount)
	recCancelAuthHandlers := append(append([]fiber.Handler{}, mws...), h.CancelRecoveryAuth)
	recCancelTokenHandlers := append(append([]fiber.Handler{}, mws...), h.CancelRecoveryToken)

	api.Post("/account/guardians/invite", gdnInviteHandlers...)
	api.Post("/account/guardians/accept", gdnAcceptHandlers...)
	api.Get("/account/guardians", gdnListHandlers...)
	api.Delete("/account/guardians/:id", gdnRevokeHandlers...)
	api.Post("/auth/recovery/initiate", recInitiateHandlers...)
	api.Post("/auth/recovery/proof/guardian", recGuardianProofHandlers...)
	api.Post("/auth/recovery/proof/old-password", recOldPassProofHandlers...)
	api.Post("/auth/recovery/proof/security-questions", recSecQuestProofHandlers...)
	api.Post("/auth/recovery/claim", recClaimHandlers...)
	api.Post("/auth/recovery/cancel", recCancelAuthHandlers...)
	api.Post("/auth/recovery/cancel/token", recCancelTokenHandlers...)
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email address format"})
	}

	userAgent := c.Get("User-Agent", "unknown")
	ipAddress := c.IP()

	if err := h.service.SendMagicLink(c.UserContext(), req.TenantID, req.Environment, req.Email, req.Name, userAgent, ipAddress); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed sending magic link"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token query parameter or body field is required"})
	}

	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	userAgent := c.Get("User-Agent", "unknown")
	ipAddress := c.IP()

	u, accessToken, refreshToken, err := h.service.VerifyMagicLinkToken(c.UserContext(), token, userAgent, ipAddress)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid or expired magic link token"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password are required"})
	}
	if !isValidEmail(req.Email) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email address format"})
	}
	if len(req.Name) > 255 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name cannot exceed 255 characters"})
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":            "password does not meet policy requirements",
					"missing_criteria": missingCriteria,
				})
			}
			policyWarning = &PolicyWarningDTO{
				MissingCriteria: missingCriteria,
			}
		}
	}

	u, accessToken, refreshToken, err := h.service.SignUpWithPassword(c.UserContext(), req.TenantID, req.Environment, req.Email, req.Password, req.Name, userAgent, ipAddress)
	if err != nil {
		if errorsIs(err, ErrUserAlreadyExists) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password are required"})
	}
	if !isValidEmail(req.Email) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email address format"})
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	u, accessToken, refreshToken, err := h.service.ValidatePasswordCredentials(c.UserContext(), req.TenantID, req.Environment, req.Email, req.Password, userAgent, ipAddress)
	if err != nil {
		if strings.Contains(err.Error(), Err2FARequired.Error()) {
			var namePtr *string
			if u != nil && u.Name != "" {
				namePtr = &u.Name
			}
			// Single source of truth: extract allowed 2FA methods directly from signed MFA token claims
			methods := []string{"totp"}
			if mfaClaims, cErr := jwtpkg.VerifyMFAChallengeToken(accessToken, h.service.config.AuthnEncryptionKey); cErr == nil && len(mfaClaims.Methods) > 0 {
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
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
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
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":          "email_verification_required",
					"message":        "email verification is required before signing in",
					"email_verified": false,
				})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "verification token query parameter is required"})
	}

	u, err := h.service.VerifyEmailToken(c.UserContext(), token)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email address format"})
	}

	if h.resendLimiter != nil {
		emailClean := strings.ToLower(strings.TrimSpace(req.Email))
		hStr := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", req.TenantID, emailClean)))
		emailHash := hex.EncodeToString(hStr[:])[:16]
		key := fmt.Sprintf("%s:resend_email:%s", req.TenantID, emailHash)

		allowed, retryAfter, err := h.resendLimiter.Check(c.UserContext(), key)
		if err != nil {
			if errors.Is(err, ratelimit.ErrRedisUnavailable) {
				return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
					"error": "rate limit service unavailable",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal rate limiter error",
			})
		}
		if !allowed {
			if retryAfter > 0 {
				c.Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
			}
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":               "too many verification email requests for this address, please try again later",
				"retry_after_seconds": int(retryAfter.Seconds()),
			})
		}
	}

	if err := h.service.ResendVerificationEmail(c.UserContext(), req.TenantID, req.Environment, req.Email); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed processing verification request"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "if an account exists with this email address, a verification link has been sent",
	})
}

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

func errorsIs(err error, target error) bool {
	return err != nil && err.Error() == target.Error()
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

// extractBearerToken extracts the JWT access token from cookies or Authorization Bearer header.
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

// EnrollTOTP handles POST /v1/client/2fa/totp/enroll.
// Generates a new TOTP secret for the authenticated user and stores it in pending state (is_enabled = false).
func (h *Handler) EnrollTOTP(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	result, err := h.service.EnrollTOTP(c.UserContext(), claims.Sub)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"secret": result.Secret,
		"uri":    result.URI,
	})
}

// ConfirmTOTP handles POST /v1/client/2fa/totp/confirm.
// Validates a 6-digit TOTP code against the pending secret and enables 2FA (is_enabled = true).
func (h *Handler) ConfirmTOTP(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	var req TOTPConfirmRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code is required"})
	}

	res, err := h.service.ConfirmTOTP(c.UserContext(), claims.Sub, strings.TrimSpace(req.Code))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// VerifyTOTP handles POST /v1/client/2fa/totp/verify and POST /v1/client/auth/2fa/verify.
// Validates a 6-digit TOTP code during login challenge or within an authenticated session.
func (h *Handler) VerifyTOTP(c *fiber.Ctx) error {
	var req TOTPVerifyRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code is required"})
	}

	mfaToken := req.MFAToken

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// 1. If MFA challenge token is provided (login 2FA verification flow)
	if mfaToken != "" {
		u, accessToken, refreshToken, err := h.service.VerifyTOTPChallenge(c.UserContext(), mfaToken, strings.TrimSpace(req.Code), req.Method, userAgent, ipAddress)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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

	// 2. Direct TOTP verification within an authenticated session
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token or two_factor_token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	if err := h.service.Verify2FACode(c.UserContext(), claims.Sub, strings.TrimSpace(req.Code), req.Method); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"valid": true,
	})
}

// DisableTOTP handles POST /v1/client/2fa/totp/disable.
// Re-verifies current password using Argon2id, removes TOTP 2FA, and revokes all active user sessions for security.
func (h *Handler) DisableTOTP(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	var req TOTPDisableRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "password is required for 2FA step-up confirmation"})
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	if err := h.service.DisableTOTP(c.UserContext(), claims.Sub, req.Password, userAgent, ipAddress); err != nil {
		if errorsIs(err, ErrInvalidCredentials) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid password confirmation"})
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	var req RecoveryCodesRegenerateRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "password is required for recovery codes regeneration step-up"})
	}

	codes, err := h.service.RegenerateRecoveryCodes(c.UserContext(), claims.Sub, req.Password)
	if err != nil {
		if errorsIs(err, ErrInvalidCredentials) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid password confirmation"})
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":        "recovery codes successfully regenerated",
		"recovery_codes": codes,
	})
}

// GetRecoveryCodesStatus handles GET /v1/client/2fa/recovery-codes/status.
// Returns remaining unused count of recovery codes for the authenticated user without exposing code values.
func (h *Handler) GetRecoveryCodesStatus(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	res, err := h.service.GetRecoveryCodesStatus(c.UserContext(), claims.Sub)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	options, sessionID, err := h.service.BeginWebAuthnRegistration(c.UserContext(), claims.Sub)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"options":    options,
		"session_id": sessionID,
	})
}

// FinishWebAuthnRegistration handles POST /v1/client/2fa/webauthn/register/finish.
func (h *Handler) FinishWebAuthnRegistration(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "session_id is required"})
	}

	httpReq, err := http.NewRequestWithContext(c.UserContext(), c.Method(), c.OriginalURL(), bytes.NewReader(c.Body()))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid http request format"})
	}
	for k, v := range c.GetReqHeaders() {
		if len(v) > 0 {
			httpReq.Header.Set(k, v[0])
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := h.service.FinishWebAuthnRegistration(c.UserContext(), claims.Sub, sessionID, httpReq, passkeyName)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// BeginWebAuthnLogin handles POST /v1/client/2fa/webauthn/login/begin.
func (h *Handler) BeginWebAuthnLogin(c *fiber.Ctx) error {
	var req WebAuthnLoginBeginRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.MFAToken) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "mfa_token is required"})
	}

	options, sessionID, userID, err := h.service.BeginWebAuthnLogin(c.UserContext(), req.MFAToken)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "mfa_token and session_id are required"})
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	clientType, err := parseAndValidateClientType(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	httpReq, err := http.NewRequestWithContext(c.UserContext(), c.Method(), c.OriginalURL(), bytes.NewReader(c.Body()))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid http request format"})
	}
	for k, v := range c.GetReqHeaders() {
		if len(v) > 0 {
			httpReq.Header.Set(k, v[0])
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	u, accessToken, refreshToken, err := h.service.FinishWebAuthnLogin(c.UserContext(), mfaToken, sessionID, httpReq, userAgent, ipAddress)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	credentials, err := h.service.ListWebAuthnPasskeys(c.UserContext(), claims.Sub)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"credentials": credentials,
	})
}

// DeleteWebAuthnPasskey handles DELETE /v1/client/2fa/webauthn/credentials/:id.
func (h *Handler) DeleteWebAuthnPasskey(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	passkeyID := c.Params("id")
	if passkeyID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "passkey id is required"})
	}

	var req PasskeyDeleteRequest
	_ = c.BodyParser(&req)

	if err := h.service.DeleteWebAuthnPasskey(c.UserContext(), claims.Sub, passkeyID, req.Password); err != nil {
		if errorsIs(err, ErrInvalidCredentials) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid password step-up confirmation required to delete your last remaining 2FA method"})
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
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
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	var req SMSEnrollRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.PhoneNumber) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "phone_number is required"})
	}

	if err := h.service.BeginSMSEnrollment(c.UserContext(), claims.Sub, strings.TrimSpace(req.PhoneNumber)); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":            "OTP verification code sent via SMS",
		"expires_in_seconds": 300,
	})
}

// ConfirmSMS handles POST /v1/client/2fa/sms/confirm.
func (h *Handler) ConfirmSMS(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	var req SMSConfirmRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code is required"})
	}

	res, err := h.service.ConfirmSMSEnrollment(c.UserContext(), claims.Sub, strings.TrimSpace(req.Code))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// DisableSMS handles DELETE /v1/client/2fa/sms/disable.
func (h *Handler) DisableSMS(c *fiber.Ctx) error {
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized: session token required"})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": fmt.Sprintf("unauthorized session: %v", err)})
	}

	var req SMSDisableRequest
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Password) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "password is required"})
	}

	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")

	if err := h.service.DisableSMS2FA(c.UserContext(), claims.Sub, req.Password, userAgent, ipAddress); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "SMS 2FA disabled successfully",
	})
}

// InviteGuardians handles POST /v1/client/account/guardians/invite. Requires step-up re-auth / fresh session.
func (h *Handler) InviteGuardians(c *fiber.Ctx) error {
	// This handler is on the /v1/client/auth router, which runs only the publishable-key
	// and rate-limit middlewares — NOT RequireClientAuth — so c.Locals("userID") is never
	// populated here. Verify the bearer token directly, as the TOTP/SMS handlers do.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required. Please step-up re-authenticate to manage recovery contacts.",
		})
	}
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required. Please step-up re-authenticate to manage recovery contacts.",
		})
	}
	userID := claims.Sub

	var req struct {
		Guardians []InviteGuardianInput `json:"guardians"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.Guardians) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid payload: must provide 1 to 5 guardian email and name objects",
		})
	}

	baseURL := fmt.Sprintf("%s://%s", c.Protocol(), c.Hostname())
	res, err := h.guardianService.InviteGuardians(c.Context(), userID, req.Guardians, baseURL)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "contact_id and token are required",
		})
	}

	if err := h.guardianService.AcceptGuardianInvite(c.Context(), req.ContactID, req.Token); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Guardian invitation accepted successfully",
	})
}

// ListGuardians handles GET /v1/client/account/guardians.
func (h *Handler) ListGuardians(c *fiber.Ctx) error {
	// /v1/client/auth router runs only pk + rate-limit middleware, so the userID local
	// is never set here. Verify the bearer token directly, like the other authed handlers.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}
	userID := claims.Sub

	dtos, err := h.guardianService.ListGuardians(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"guardians": dtos,
	})
}

// RevokeGuardian handles DELETE /v1/client/account/guardians/:id.
func (h *Handler) RevokeGuardian(c *fiber.Ctx) error {
	// /v1/client/auth router runs only pk + rate-limit middleware, so the userID local
	// is never set here. Verify the bearer token directly, like the other authed handlers.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authentication required",
		})
	}
	userID := claims.Sub

	contactID := c.Params("id")
	if contactID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Guardian contact ID is required",
		})
	}

	if err := h.guardianService.RevokeGuardian(c.Context(), userID, contactID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "email address is required",
		})
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
	if errors.Is(err, ErrNoRecoveryMethodsAvailable) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "no_recovery_methods_available",
			"message": "No account recovery methods are configured for this account. Please contact system support for administrative assistance.",
		})
	}
	if errors.Is(err, ErrOriginBlacklisted) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "origin_blacklisted",
			"message": "origin IP, subnet, or device fingerprint is temporarily blacklisted following a security cancellation",
		})
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		SharePayload     string `json:"share_payload"`
	}

	if err := c.BodyParser(&req); err != nil || req.RecoveryRequestID == "" || req.SharePayload == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "recovery_request_id and share_payload are required",
		})
	}

	thresholdReached, err := h.recoveryService.SubmitGuardianShareProof(c.Context(), req.RecoveryRequestID, req.SharePayload)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "recovery_request_id and password are required",
		})
	}

	if err := h.recoveryService.SubmitOldPasswordProof(c.Context(), req.RecoveryRequestID, req.Password); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "recovery_request_id is required",
		})
	}

	if err := h.recoveryService.SubmitSecurityQuestionsProof(c.Context(), req.RecoveryRequestID, req.Answers); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "request_id, claim_token, and new_password are required",
		})
	}

	req.IPAddress = c.IP()
	req.UserAgent = c.Get("User-Agent")
	req.AcceptLang = c.Get("Accept-Language")

	res, err := h.recoveryService.ClaimAccount(c.Context(), req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "recovery_request_id is required",
		})
	}

	// /v1/client/auth router runs only pk + rate-limit middleware, so the userID/sessionID
	// locals are never set here — previously this handler passed an empty userID straight to
	// the service (unauthenticated). Verify the bearer token directly and require a valid
	// session, matching the other authenticated handlers in this file.
	tokenStr := extractBearerToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized: session token required",
		})
	}
	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.config.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": fmt.Sprintf("unauthorized session: %v", err),
		})
	}
	userID := claims.Sub
	sessionID := claims.SessionID

	if err := h.recoveryService.CancelRecoveryRequestByAuthenticatedSession(c.Context(), userID, req.RecoveryRequestID, sessionID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "cancellation_token is required",
		})
	}

	if err := h.recoveryService.CancelRecoveryRequestBySignedToken(c.Context(), req.CancellationToken); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "cancelled",
		"message": "Recovery request successfully cancelled. Originating request details blacklisted for 7 days. Account flagged for security review.",
	})
}



