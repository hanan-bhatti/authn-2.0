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
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
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

// getTenantID resolves the tenant for this request from the locals set by the
// authenticating middleware, or returns "" when no tenant could be resolved.
//
// M3 (same class as internal/org/handler.go): this used to fall back to the
// literal "tnt_default", so a request that reached a handler without a resolved
// tenant silently mutated a real production tenant's user records. Every route
// that reads the tenant is mounted behind the publishable-key and client-session
// middleware, both of which set tenant_id on success and reject the request
// otherwise, so failing closed here breaks no legitimate flow.
func getTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// requireTenantID returns the resolved tenant, or a written 401 response when the
// tenant is unknown. Callers must return the response as-is when ok is false.
func requireTenantID(c *fiber.Ctx) (string, error, bool) {
	tenantID := getTenantID(c)
	if tenantID == "" {
		return "", httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request"), false
	}
	return tenantID, nil, true
}

func getEnvironment(c *fiber.Ctx) string {
	if val, ok := c.Locals("environment").(string); ok && val != "" {
		return val
	}
	return "test"
}

// badRequestLogged answers with a 400 carrying a static, client-safe message while
// keeping the underlying error server-side.
//
// The service layer wraps ent/SQL failures (`failed updating user profile: %w`,
// `failed saving pending email token: %w`, ...) and returns them through the same
// branch as genuine validation failures. These branches must stay 4xx for API
// compatibility, so the client gets a fixed message and the real error is logged
// in SendInternal's format instead of being echoed back.
func badRequestLogged(c *fiber.Ctx, op string, err error, code httperr.Code, msg string) error {
	if err != nil {
		log.Printf("[error] %s %s %s: %v", c.Method(), c.Path(), op, err)
	}
	return httperr.BadRequest(c, code, msg)
}

func (h *Handler) RegisterRoutes(app *fiber.App, clientAuthMw, pkMw fiber.Handler) {
	// ONE group on this prefix. Two groups on the same prefix both matched every
	// protected request, so pkMw ran twice — two ValidateKey DB round-trips per
	// request on the hottest path in the user API — and a route's authentication
	// depended on which side of the group boundary its registration line happened
	// to sit on. Moving a line was enough to silently expose or protect a route
	// (audit finding M4).
	//
	// pkMw stays group-wide: every route here requires a publishable key.
	// clientAuthMw is attached PER ROUTE so each line declares its own auth.
	group := app.Group("/v1/client/user")
	if pkMw != nil {
		group.Use(pkMw)
	}

	// Public: publishable key only. Caller identity comes from the signed token
	// in the query string, which the handler verifies itself.
	group.Get("/email/verify", h.VerifyEmailChange)
	group.Get("/recovery-email/verify", h.VerifyRecoveryEmail)

	// Protected: publishable key + an authenticated user session.
	var auth []fiber.Handler
	if clientAuthMw != nil {
		auth = []fiber.Handler{clientAuthMw}
	}
	protected := func(h fiber.Handler) []fiber.Handler {
		return append(append([]fiber.Handler{}, auth...), h)
	}

	group.Get("/profile", protected(h.GetProfile)...)
	group.Patch("/profile", protected(h.UpdateProfile)...)
	group.Post("/password", protected(h.ChangePassword)...)
	group.Post("/email", protected(h.RequestEmailChange)...)
	group.Get("/recovery-email", protected(h.GetRecoveryEmail)...)
	group.Post("/recovery-email", protected(h.SetRecoveryEmail)...)
	group.Delete("/recovery-email", protected(h.DeleteRecoveryEmail)...)
	group.Get("/social-accounts", protected(h.ListSocialAccounts)...)
	group.Delete("/social-accounts/:provider", protected(h.UnlinkSocialAccount)...)
	group.Delete("/account", protected(h.DeleteAccount)...)
}

func (h *Handler) GetProfile(c *fiber.Ctx) error {
	userID := getUserID(c)

	prof, err := h.svc.GetProfile(c.UserContext(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, ErrUserNotFound.Error())
		}
		return httperr.SendInternal(c, "user.get_profile", err)
	}

	return c.Status(http.StatusOK).JSON(prof)
}

func (h *Handler) UpdateProfile(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	prof, err := h.svc.UpdateProfile(c.UserContext(), userID, req)
	if err != nil {
		return badRequestLogged(c, "user.update_profile", err, httperr.CodeValidationFailed,
			"profile could not be updated: one or more fields are invalid")
	}

	return c.Status(http.StatusOK).JSON(prof)
}

func (h *Handler) ChangePassword(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	env := getEnvironment(c)

	var req ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if req.NewPassword == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "new_password is required")
	}

	err := h.svc.ChangePassword(c.UserContext(), tenantID, env, userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, ErrIncorrectPassword) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, ErrIncorrectPassword.Error())
		}
		return badRequestLogged(c, "user.change_password", err, httperr.CodeValidationFailed,
			"password could not be changed: ensure the new password meets the configured password policy")
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "password updated successfully",
	})
}

func (h *Handler) RequestEmailChange(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	env := getEnvironment(c)

	var req RequestEmailChangeRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	_, err := h.svc.RequestEmailChange(c.UserContext(), tenantID, env, userID, req.NewEmail)
	if err != nil {
		if errors.Is(err, ErrEmailAlreadyInUse) {
			return httperr.Conflict(c, httperr.CodeAlreadyExists, ErrEmailAlreadyInUse.Error())
		}
		return badRequestLogged(c, "user.request_email_change", err, httperr.CodeValidationFailed,
			"email change request could not be processed")
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "email verification link sent to new email address",
	})
}

func (h *Handler) VerifyEmailChange(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "token query parameter is required")
	}

	err := h.svc.VerifyEmailChange(c.UserContext(), token)
	if err != nil {
		if errors.Is(err, ErrInvalidVerificationToken) {
			return httperr.BadRequest(c, httperr.CodeInvalidToken, ErrInvalidVerificationToken.Error())
		}
		return httperr.SendInternal(c, "user.verify_email_change", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "primary email address updated and verified successfully",
	})
}

func (h *Handler) GetRecoveryEmail(c *fiber.Ctx) error {
	userID := getUserID(c)

	prof, err := h.svc.GetProfile(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "user.get_recovery_email", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"recovery_email":          prof.RecoveryEmail,
		"recovery_email_verified": prof.RecoveryEmailVerified,
	})
}

func (h *Handler) SetRecoveryEmail(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	env := getEnvironment(c)

	var req SetRecoveryEmailRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	_, err := h.svc.SetRecoveryEmail(c.UserContext(), tenantID, env, userID, req.RecoveryEmail)
	if err != nil {
		return badRequestLogged(c, "user.set_recovery_email", err, httperr.CodeValidationFailed,
			"recovery email could not be set")
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "secondary recovery email verification link sent",
	})
}

func (h *Handler) VerifyRecoveryEmail(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "token query parameter is required")
	}

	err := h.svc.VerifyRecoveryEmail(c.UserContext(), token)
	if err != nil {
		if errors.Is(err, ErrInvalidVerificationToken) {
			return httperr.BadRequest(c, httperr.CodeInvalidToken, ErrInvalidVerificationToken.Error())
		}
		return httperr.SendInternal(c, "user.verify_recovery_email", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "secondary recovery email verified successfully",
	})
}

func (h *Handler) DeleteRecoveryEmail(c *fiber.Ctx) error {
	userID := getUserID(c)

	err := h.svc.DeleteRecoveryEmail(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "user.delete_recovery_email", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "secondary recovery email removed successfully",
	})
}

func (h *Handler) ListSocialAccounts(c *fiber.Ctx) error {
	userID := getUserID(c)

	accounts, err := h.svc.ListSocialAccounts(c.UserContext(), userID)
	if err != nil {
		return httperr.SendInternal(c, "user.list_social_accounts", err)
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
			return httperr.NotFound(c, httperr.CodeNotFound, ErrSocialNotConnected.Error())
		}
		if errors.Is(err, ErrCannotUnlinkLastAuth) {
			return httperr.Forbidden(c, httperr.CodeForbidden, ErrCannotUnlinkLastAuth.Error())
		}
		return badRequestLogged(c, "user.unlink_social_account", err, httperr.CodeValidationFailed,
			"social account could not be unlinked")
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"provider": provider,
		"message":  "social account unlinked successfully",
	})
}

func (h *Handler) DeleteAccount(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	env := getEnvironment(c)

	var req DeleteAccountRequest
	_ = c.BodyParser(&req)

	err := h.svc.DeleteAccount(c.UserContext(), tenantID, env, userID, req.Password)
	if err != nil {
		if errors.Is(err, ErrIncorrectPassword) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, ErrIncorrectPassword.Error())
		}
		return httperr.SendInternal(c, "user.delete_account", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "user account deleted permanently",
	})
}
