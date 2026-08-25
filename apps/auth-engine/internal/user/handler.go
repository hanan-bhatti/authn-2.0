/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/handler.go
 * Tier: HTTP Controller Layer / Fiber Endpoints
 *
 * Description: Fiber handlers for the user self-service API (/v1/client/user): profile,
 *              password, primary and recovery email, linked social accounts and account
 *              erasure. Resolves the caller from middleware locals and maps the package
 *              sentinels onto the canonical error envelope.
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/username"
)

// codeTOTPRequired marks a destructive operation that needs an authenticator code
// because the account holds no password to re-enter.
//
// Declared here rather than in httperr because it is specific to this surface, the
// same way internal/impersonation declares its own step-up code. A client branches
// on it to swap the password prompt for a code prompt.
const codeTOTPRequired httperr.Code = "totp_required"

// Handler exposes the user self-service operations over HTTP.
type Handler struct {
	// svc carries out the operation behind each route.
	svc *Service
}

// NewHandler constructs a user Handler over svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// getUserID returns the authenticated caller's ID from the locals set by the
// client-session middleware, or "" when the request carried no session.
func getUserID(c *fiber.Ctx) string {
	if val, ok := c.Locals("userID").(string); ok && val != "" {
		return val
	}
	if val, ok := c.Locals("user_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// getTenantID returns the tenant resolved by the authenticating middleware, or
// "" when none was resolved.
//
// There is deliberately no default tenant: a request that reaches a handler with
// no resolved tenant is not authenticated, and substituting one would let it read
// and write a real tenant's user records.
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

// getEnvironment returns the request's environment, defaulting to "test" when
// the middleware set none.
func getEnvironment(c *fiber.Ctx) string {
	if val, ok := c.Locals("environment").(string); ok && val != "" {
		return val
	}
	return "test"
}

// badRequestLogged answers with a 400 carrying a static, client-safe message
// while keeping the underlying error server-side.
//
// The service layer returns wrapped ent/SQL failures through the same branch as
// genuine validation failures. These branches answer 4xx, so the caller gets a
// fixed message and the real error is logged rather than echoed back, which would
// disclose table and column names.
func badRequestLogged(c *fiber.Ctx, op string, err error, code httperr.Code, msg string) error {
	if err != nil {
		log.Printf("[error] %s %s %s: %v", c.Method(), c.Path(), op, err)
	}
	return httperr.BadRequest(c, code, msg)
}

// RegisterRoutes mounts the user self-service routes under /v1/client/user.
//
// Exactly one group owns this prefix, because two groups on the same prefix both
// match every request and would run pkMw twice per call. pkMw is group-wide:
// every route here requires a publishable key. clientAuthMw is attached per route
// instead, so each line declares its own authentication and a route's protection
// does not depend on where its registration sits relative to a group boundary.
func (h *Handler) RegisterRoutes(app *fiber.App, clientAuthMw, pkMw fiber.Handler) {
	group := app.Group("/v1/client/user")
	if pkMw != nil {
		group.Use(pkMw)
	}

	// Publishable key only. Caller identity comes from the signed token in the
	// query string, which the handler verifies itself.
	group.Get("/email/verify", h.VerifyEmailChange)
	group.Get("/recovery-email/verify", h.VerifyRecoveryEmail)

	// Publishable key plus an authenticated user session.
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

// GetProfile returns the caller's own profile. Answers 404 when the account no
// longer exists.
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

// UpdateProfile applies a partial update to the caller's profile and returns the
// result. Answers 409 when the requested handle is held by another account, 422
// when it breaks a naming rule or names a reserved metadata key, and 400 when any
// other field fails validation.
func (h *Handler) UpdateProfile(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	prof, err := h.svc.UpdateProfile(c.UserContext(), userID, req)
	if err != nil {
		switch {
		case errors.Is(err, ErrUsernameTaken):
			return httperr.Conflict(c, httperr.CodeAlreadyExists, ErrUsernameTaken.Error())
		case errors.Is(err, ErrUsernameInvalid):
			// The rule that was broken, not the fact that something was: a form told
			// only "invalid" leaves the user to guess which of six rules they missed.
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed, username.Explain(err))
		case errors.Is(err, ErrReservedMetadataKey):
			// The wrapped message names the key, so it is passed through rather than
			// replaced with a fixed string the caller cannot act on.
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed, err.Error())
		}
		return badRequestLogged(c, "user.update_profile", err, httperr.CodeValidationFailed,
			"profile could not be updated: one or more fields are invalid")
	}

	return c.Status(http.StatusOK).JSON(prof)
}

// ChangePassword changes the caller's password. Answers 400 without a new
// password or when the policy is unmet, and 401 when the current password is wrong.
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

// RequestEmailChange mails a confirmation link to a proposed new primary address.
//
// The response never carries the token, which reaches the user only through the
// new address. Answers 409 when the address is already in use.
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

// VerifyEmailChange consumes the token from the query string and promotes the
// pending address to primary. Answers 400 for a missing, unknown or expired token.
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

// GetRecoveryEmail returns the caller's secondary recovery address and whether it
// has been verified.
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

// SetRecoveryEmail registers a secondary recovery address and mails it a
// confirmation link. Answers 400 when the address fails validation.
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

// VerifyRecoveryEmail consumes the token from the query string and marks the
// recovery address verified. Answers 400 for a missing, unknown or expired token.
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

// DeleteRecoveryEmail removes the caller's secondary recovery address.
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

// ListSocialAccounts returns the OAuth identities linked to the caller's account.
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

// UnlinkSocialAccount disconnects the provider named in the path. Answers 404
// when it is not linked and 403 when it is the account's only way to sign in.
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

// DeleteAccount permanently erases the caller's account.
//
// Answers 401 when the confirming password is wrong, 401 with
// `totp_required` when the account has no password and no code was supplied,
// 401 when that code is wrong, and 409 when the account is the only administrator
// of an organization other people still belong to — with those organizations
// listed under `details.organizations`, so the client can name them and link to
// each one instead of telling the reader to go and look.
func (h *Handler) DeleteAccount(c *fiber.Ctx) error {
	userID := getUserID(c)
	tenantID, errResp, ok := requireTenantID(c)
	if !ok {
		return errResp
	}
	env := getEnvironment(c)

	var req DeleteAccountRequest
	_ = c.BodyParser(&req)

	err := h.svc.DeleteAccount(c.UserContext(), tenantID, env, userID, req.Password, req.TOTPCode)
	if err != nil {
		if errors.Is(err, ErrIncorrectPassword) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, ErrIncorrectPassword.Error())
		}
		// Its own code, not CodeInvalidCredentials: nothing the caller sent was
		// wrong, so a client branching on the code needs to tell "ask for a code"
		// apart from "that was rejected".
		if errors.Is(err, ErrTOTPRequired) {
			return httperr.Unauthorized(c, codeTOTPRequired, ErrTOTPRequired.Error())
		}
		if errors.Is(err, ErrIncorrectTOTP) {
			return httperr.Unauthorized(c, httperr.CodeInvalidCredentials, ErrIncorrectTOTP.Error())
		}
		var soleAdmin *SoleOrgAdminError
		if errors.As(err, &soleAdmin) {
			return httperr.ConflictWithDetails(c, httperr.CodeConflict, soleAdmin.Error(), map[string]interface{}{
				"organizations": soleAdmin.Organizations,
			})
		}
		return httperr.SendInternal(c, "user.delete_account", err)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"message": "user account deleted permanently",
	})
}
