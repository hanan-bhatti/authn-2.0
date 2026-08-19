/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/auth_handlers.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber HTTP handlers for primary auth flows (signup, login, email verification, magic link).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/accountstatus"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// SendMagicLink handles requests to send a passwordless magic login link.
func (h *Handler) SendMagicLink(c *fiber.Ctx) error {
	var req SendMagicLinkDTO
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}
	req.TenantID = tenantID

	req.Environment = middleware.GetEnvironment(c)

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
		if accountstatus.Refused(err) {
			return httperr.Send(c, fiber.StatusForbidden, httperr.CodeAccountDisabled, accountstatus.PublicMessage(err))
		}
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
		h.cookies.SetRefreshToken(c, u.TenantID, string(u.Environment), refreshToken,
			h.cookies.RefreshTokenTTL(c.UserContext(), u.TenantID, string(u.Environment)))
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

	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}
	req.TenantID = tenantID

	req.Environment = middleware.GetEnvironment(c)
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
		pol, err := h.policyRepo.GetPasswordPolicy(c.UserContext(), req.TenantID, req.Environment)
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
		// An unknown tenant is a misconfigured client, not a server fault: the
		// publishable key names the tenant, so reaching here means the key and
		// the request disagree, or no tenant was ever provisioned.
		if errors.Is(err, ErrTenantNotFound) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed,
				"unknown tenant: no tenant has been provisioned for this request")
		}
		return httperr.SendInternal(c, "auth.signup", err)
	}

	// Check tenant security policy compliance (require_email_verification notice on signup)
	if h.policyRepo != nil {
		secPol, err := h.policyRepo.GetSecurityPolicy(c.UserContext(), req.TenantID, req.Environment)
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
		h.cookies.SetRefreshToken(c, u.TenantID, string(u.Environment), refreshToken,
			h.cookies.RefreshTokenTTL(c.UserContext(), u.TenantID, string(u.Environment)))
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

	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}
	req.TenantID = tenantID

	req.Environment = middleware.GetEnvironment(c)

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
		// A restriction an administrator placed is answered distinctly from a bad
		// password. Collapsing it into invalid_credentials sends the account holder
		// into a password reset that cannot help them, and the reset would succeed,
		// leaving them with a working password they still cannot sign in with.
		if accountstatus.Refused(err) {
			return httperr.Send(c, fiber.StatusForbidden, httperr.CodeAccountDisabled, accountstatus.PublicMessage(err))
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
		pol, err := h.policyRepo.GetPasswordPolicy(c.UserContext(), req.TenantID, req.Environment)
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
		secPol, err := h.policyRepo.GetSecurityPolicy(c.UserContext(), req.TenantID, req.Environment)
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
		h.cookies.SetRefreshToken(c, u.TenantID, string(u.Environment), refreshToken,
			h.cookies.RefreshTokenTTL(c.UserContext(), u.TenantID, string(u.Environment)))
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

// VerifyEmail handles email verification link requests (GET /v1/client/auth/verify-email?token=...).
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

// ResendVerification handles resending verification emails (POST /v1/client/auth/resend-verification).
func (h *Handler) ResendVerification(c *fiber.Ctx) error {
	var req struct {
		Email string `json:"email"`
		// Resolved from the credential below; excluded from JSON so the body
		// cannot name a tenant or select an environment.
		TenantID    string `json:"-"`
		Environment string `json:"-"`
	}

	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}
	req.TenantID = tenantID

	req.Environment = middleware.GetEnvironment(c)

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
