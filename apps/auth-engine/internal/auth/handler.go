/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/handler.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber HTTP handlers for client authentication endpoints (signup, login).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
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

// AuthResponse defines the successful authentication response payload.
type AuthResponse struct {
	User          UserDTO           `json:"user"`
	AccessToken   string            `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken  string            `json:"refresh_token,omitempty" example:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
	PolicyWarning *PolicyWarningDTO `json:"policy_warning,omitempty"`
}

// PolicyWarningDTO contains password compliance notices returned during login/signup.
type PolicyWarningDTO struct {
	RequiresPasswordUpgrade bool     `json:"requires_password_upgrade,omitempty"`
	MissingCriteria         []string `json:"missing_criteria,omitempty"`
}

// UserDTO defines the public profile payload returned to clients.
type UserDTO struct {
	ID        string  `json:"id" example:"usr_1a2b3c"`
	Email     string  `json:"email" example:"user@example.com"`
	Name      *string `json:"name,omitempty" example:"Alex Smith"`
	Status    string  `json:"status" example:"active"`
	CreatedAt string  `json:"created_at" example:"2026-08-01T12:00:00Z"`
}

// Handler handles HTTP requests for authentication flows.
type Handler struct {
	service    *Service
	policyRepo *policy.Repository
}

// NewHandler constructs a new Auth Handler instance.
func NewHandler(service *Service, policyRepo *policy.Repository) *Handler {
	return &Handler{
		service:    service,
		policyRepo: policyRepo,
	}
}

// RegisterRoutes attaches authentication endpoints to the Fiber app.
func (h *Handler) RegisterRoutes(app *fiber.App) {
	api := app.Group("/v1/client")
	api.Post("/signup", h.SignUp)
	api.Post("/login", h.Login)
}

// SignUp handles user registration requests.
//
// @Summary Client Password Signup
// @Description Registers a new user with password credentials, issues a short-lived JWT access token, and sets a secure HttpOnly refresh cookie (or returns refresh token in JSON for native apps).
// @Tags Client Auth
// @Accept json
// @Produce json
// @Param request body SignUpRequest true "Signup Request Payload"
// @Success 201 {object} AuthResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Router /v1/client/signup [post]
func (h *Handler) SignUp(c *fiber.Ctx) error {
	var req SignUpRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.TenantID == "" {
		req.TenantID = "tnt_default"
	}
	if req.Environment == "" {
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

	// Validate tenant password policy
	var policyWarning *PolicyWarningDTO
	pol, err := h.policyRepo.GetPasswordPolicy(c.Context(), req.TenantID)
	if err == nil {
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

	u, accessToken, refreshToken, err := h.service.SignUpWithPassword(c.Context(), req.TenantID, req.Environment, req.Email, req.Password, req.Name, userAgent, ipAddress)
	if err != nil {
		if errorsIs(err, ErrUserAlreadyExists) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
			Secure:   false,
			SameSite: "Lax",
			Path:     "/v1/client",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(AuthResponse{
		User: UserDTO{
			ID:        u.ID,
			Email:     u.Email,
			Name:      namePtr,
			Status:    string(u.Status),
			CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:   accessToken,
		RefreshToken:  refreshTokenBody,
		PolicyWarning: policyWarning,
	})
}

// Login handles password authentication requests.
//
// @Summary Client Password Login
// @Description Authenticates user password credentials, issues a short-lived JWT access token, and sets a secure HttpOnly refresh cookie (or returns refresh token in JSON for native apps).
// @Tags Client Auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login Request Payload"
// @Success 200 {object} AuthResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /v1/client/login [post]
func (h *Handler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.TenantID == "" {
		req.TenantID = "tnt_default"
	}
	if req.Environment == "" {
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

	u, accessToken, refreshToken, err := h.service.ValidatePasswordCredentials(c.Context(), req.TenantID, req.Environment, req.Email, req.Password, userAgent, ipAddress)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	// Check password policy compliance & force upgrade flags on login
	var policyWarning *PolicyWarningDTO
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
			Secure:   false,
			SameSite: "Lax",
			Path:     "/v1/client",
		})
	}

	return c.Status(fiber.StatusOK).JSON(AuthResponse{
		User: UserDTO{
			ID:        u.ID,
			Email:     u.Email,
			Name:      namePtr,
			Status:    string(u.Status),
			CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		},
		AccessToken:   accessToken,
		RefreshToken:  refreshTokenBody,
		PolicyWarning: policyWarning,
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
