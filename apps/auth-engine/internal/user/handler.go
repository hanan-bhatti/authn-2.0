/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/handler.go
 * Tier: HTTP REST Route Handler Layer
 *
 * Description: Fiber REST API route handlers for User Self-Service Profile,
 *              Password, Recovery Email, Email Change, Social Account Unlinking,
 *              and Account Erasure.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func getUserID(c *fiber.Ctx) string {
	if val, ok := c.Locals("userID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("user_id").(string); ok && val != "" {
		return val
	}
	return ""
}

func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return "tnt_default"
}

func getEnvironment(c *fiber.Ctx) string {
	if val, ok := c.Locals("environment").(string); ok && val != "" {
		return val
	}
	return "test"
}

func (h *Handler) RegisterRoutes(app *fiber.App, clientAuthMw, pkMw fiber.Handler) {
	// Public verification routes (token verification callbacks)
	pubGroup := app.Group("/v1/client/user")
	if pkMw != nil {
		pubGroup.Use(pkMw)
	}
	pubGroup.Get("/email/verify", h.VerifyEmailChange)
	pubGroup.Get("/recovery-email/verify", h.VerifyRecoveryEmail)

	// Protected user profile & settings endpoints
	group := app.Group("/v1/client/user")
	if pkMw != nil {
		group.Use(pkMw)
	}
	if clientAuthMw != nil {
		group.Use(clientAuthMw)
	}

	group.Get("/profile", h.GetProfile)
	group.Patch("/profile", h.UpdateProfile)
	group.Post("/password", h.ChangePassword)
	group.Post("/email", h.RequestEmailChange)
	group.Get("/recovery-email", h.GetRecoveryEmail)
	group.Post("/recovery-email", h.SetRecoveryEmail)
	group.Delete("/recovery-email", h.DeleteRecoveryEmail)
	group.Get("/social-accounts", h.ListSocialAccounts)
	group.Delete("/social-accounts/:provider", h.UnlinkSocialAccount)
	group.Delete("/account", h.DeleteAccount)
}

func (h *Handler) GetProfile(c *fiber.Ctx) error {
	userID := getUserID(c)

	prof, err := h.svc.GetProfile(c.UserContext(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(prof)
}

func (h *Handler) UpdateProfile(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}

	prof, err := h.svc.UpdateProfile(c.UserContext(), userID, req)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(prof)
}

func (h *Handler) ChangePassword(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID := getTenantID(c)
	env := getEnvironment(c)

	var req ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}

	if req.NewPassword == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "new_password is required"})
	}

	err := h.svc.ChangePassword(c.UserContext(), tenantID, env, userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, ErrIncorrectPassword) {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "password updated successfully",
	})
}

func (h *Handler) RequestEmailChange(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID := getTenantID(c)
	env := getEnvironment(c)

	var req RequestEmailChangeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}

	_, err := h.svc.RequestEmailChange(c.UserContext(), tenantID, env, userID, req.NewEmail)
	if err != nil {
		if errors.Is(err, ErrEmailAlreadyInUse) {
			return c.Status(http.StatusConflict).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "email verification link sent to new email address",
	})
}

func (h *Handler) VerifyEmailChange(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "token query parameter is required"})
	}

	err := h.svc.VerifyEmailChange(c.UserContext(), token)
	if err != nil {
		if errors.Is(err, ErrInvalidVerificationToken) {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "primary email address updated and verified successfully",
	})
}

func (h *Handler) GetRecoveryEmail(c *fiber.Ctx) error {
	userID := getUserID(c)

	prof, err := h.svc.GetProfile(c.UserContext(), userID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"recovery_email":          prof.RecoveryEmail,
		"recovery_email_verified": prof.RecoveryEmailVerified,
	})
}

func (h *Handler) SetRecoveryEmail(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID := getTenantID(c)
	env := getEnvironment(c)

	var req SetRecoveryEmailRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}

	_, err := h.svc.SetRecoveryEmail(c.UserContext(), tenantID, env, userID, req.RecoveryEmail)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "secondary recovery email verification link sent",
	})
}

func (h *Handler) VerifyRecoveryEmail(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "token query parameter is required"})
	}

	err := h.svc.VerifyRecoveryEmail(c.UserContext(), token)
	if err != nil {
		if errors.Is(err, ErrInvalidVerificationToken) {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "secondary recovery email verified successfully",
	})
}

func (h *Handler) DeleteRecoveryEmail(c *fiber.Ctx) error {
	userID := getUserID(c)

	err := h.svc.DeleteRecoveryEmail(c.UserContext(), userID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "secondary recovery email removed successfully",
	})
}

func (h *Handler) ListSocialAccounts(c *fiber.Ctx) error {
	userID := getUserID(c)

	accounts, err := h.svc.ListSocialAccounts(c.UserContext(), userID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"social_accounts": accounts,
	})
}

func (h *Handler) UnlinkSocialAccount(c *fiber.Ctx) error {
	userID := getUserID(c)
	provider := c.Params("provider")

	err := h.svc.UnlinkSocialAccount(c.UserContext(), userID, provider)
	if err != nil {
		if errors.Is(err, ErrSocialNotConnected) {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, ErrCannotUnlinkLastAuth) {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"provider": provider,
		"message":  "social account unlinked successfully",
	})
}

func (h *Handler) DeleteAccount(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID := getTenantID(c)
	env := getEnvironment(c)

	var req DeleteAccountRequest
	_ = c.BodyParser(&req)

	err := h.svc.DeleteAccount(c.UserContext(), tenantID, env, userID, req.Password)
	if err != nil {
		if errors.Is(err, ErrIncorrectPassword) {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "user account deleted permanently",
	})
}
