/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/security_questions_handlers.go
 * Tier: Internal Feature Package / HTTP Handlers
 *
 * Description: Fiber handlers for the account holder's security-question roster under
 *              /v1/client/account/security-questions: read, replace and remove.
 *
 * Security Notice:
 *   - Writing or removing the roster takes a step-up: the account's password, or a current
 *     authenticator code when it has no password. The session alone is not enough.
 *   - Responses carry prompts only. Answer digests never leave the engine.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// codeStepUpRequired marks a security-question write that needs a credential the
// caller did not send.
//
// Its own code so a client can swap the prompt for the factor the account actually
// holds, rather than reporting a rejection for something the user was never asked
// to provide.
const codeStepUpRequired httperr.Code = "step_up_required"

// stepUpForSecurityQuestions re-proves the caller's identity before the recovery
// roster is written.
//
// Security questions are the one recovery factor a caller can enroll entirely on
// its own. A guardian has to accept an invitation from their own mailbox and a
// recovery address has to be confirmed from that address, so neither can be planted
// by whoever is merely holding a session. Answers only need to be typed, which
// makes an unattended session enough to install a permanent way back into the
// account — one that survives a password change and a full session revocation,
// because recovery is designed to survive exactly those.
//
// The order is fixed rather than the caller's choice: an account with a password is
// checked on the password, and only one without falls through to TOTP. An account
// holding neither has nothing left to prove with, and the session stands — refusing
// there would leave a social-only account unable to enroll the one recovery method
// that needs no second party.
//
// It writes its own response and returns false when the caller has not proven
// enough; callers must return that response unchanged.
func (h *Handler) stepUpForSecurityQuestions(c *fiber.Ctx, userID, password, totpCode string) bool {
	u, err := h.service.repo.FindUserByID(c.UserContext(), userID)
	if err != nil || u == nil {
		_ = httperr.NotFound(c, httperr.CodeNotFound, "user account not found")
		return false
	}

	if u.PasswordHash != "" {
		if strings.TrimSpace(password) == "" {
			_ = httperr.Unauthorized(c, codeStepUpRequired,
				"enter your current password to change your security questions")
			return false
		}
		if err := h.service.VerifyAdminPassword(c.UserContext(), userID, password); err != nil {
			_ = httperr.Unauthorized(c, httperr.CodeInvalidCredentials,
				"that password is not correct: enter your current password to change your security questions")
			return false
		}
		return true
	}

	// Asked of the store rather than inferred from the request, so a caller cannot skip
	// the check by omitting the code.
	method, err := h.service.repo.GetActiveTOTPMethodForUser(c.UserContext(), userID)
	if err != nil || method == nil {
		return true
	}

	if strings.TrimSpace(totpCode) == "" {
		_ = httperr.Unauthorized(c, codeStepUpRequired,
			"enter the 6-digit code from your authenticator app to change your security questions: this account has no password to re-enter")
		return false
	}
	if err := h.service.VerifyAdminTOTP(c.UserContext(), userID, strings.TrimSpace(totpCode)); err != nil {
		_ = httperr.Unauthorized(c, httperr.CodeInvalidCredentials,
			"that authenticator code is not valid right now: check the current code and try again")
		return false
	}
	return true
}

// ListSecurityQuestions handles GET /v1/client/account/security-questions.
//
// It answers 200 with the enrolled prompts, or 404 when the account has none — the
// account holder is asking whether this method is set up, and an empty list is a
// less direct way of saying it is not.
func (h *Handler) ListSecurityQuestions(c *fiber.Ctx) error {
	userID := getUserID(c)

	questions, err := h.recoveryService.ListSecurityQuestions(c.UserContext(), userID)
	if err != nil {
		if errors.Is(err, ErrNoSecurityQuestions) {
			return httperr.NotFound(c, httperr.CodeNotFound,
				"no security questions are set up on this account yet")
		}
		return httperr.SendInternal(c, "auth.security_questions.list", err)
	}

	return c.JSON(fiber.Map{
		"security_questions": questions,
		"total":              len(questions),
	})
}

// SetSecurityQuestions handles PUT /v1/client/account/security-questions.
//
// PUT rather than POST because the whole roster is replaced: the request states what
// the set is, not what to add to it. It answers 200 with the saved prompts, 401 when
// the step-up is missing or wrong, and 422 for a set that breaks a rule.
func (h *Handler) SetSecurityQuestions(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req struct {
		Questions []SecurityQuestionInput `json:"questions"`
		// Password and TOTPCode carry the step-up. Only the one the account can be
		// checked on is read; see stepUpForSecurityQuestions.
		Password string `json:"password,omitempty"`
		TOTPCode string `json:"totp_code,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if !h.stepUpForSecurityQuestions(c, userID, req.Password, req.TOTPCode) {
		return nil
	}

	questions, err := h.recoveryService.SetSecurityQuestions(c.UserContext(), userID, req.Questions)
	if err != nil {
		// Both carry a message naming the rule and the entry that broke it, so the text
		// is passed through rather than replaced by one the caller cannot act on.
		if errors.Is(err, ErrSecurityQuestionCount) || errors.Is(err, ErrSecurityQuestionInvalid) {
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed, err.Error())
		}
		return httperr.SendInternal(c, "auth.security_questions.set", err)
	}

	return c.JSON(fiber.Map{
		"security_questions": questions,
		"total":              len(questions),
		"message":            "security questions saved: you will be asked for all of them if you ever need to recover this account",
	})
}

// DeleteSecurityQuestions handles DELETE /v1/client/account/security-questions.
//
// It answers 200 whether or not anything was enrolled: the caller asked for the
// account to have no security questions, and it now does not.
func (h *Handler) DeleteSecurityQuestions(c *fiber.Ctx) error {
	userID := getUserID(c)

	var req struct {
		Password string `json:"password,omitempty"`
		TOTPCode string `json:"totp_code,omitempty"`
	}
	// A DELETE may legitimately carry no body; the step-up below reports what is
	// missing, so an unparseable one is not a separate failure.
	_ = c.BodyParser(&req)

	if !h.stepUpForSecurityQuestions(c, userID, req.Password, req.TOTPCode) {
		return nil
	}

	if err := h.recoveryService.DeleteSecurityQuestions(c.UserContext(), userID); err != nil {
		return httperr.SendInternal(c, "auth.security_questions.delete", err)
	}

	return c.JSON(fiber.Map{
		"message": "security questions removed: they can no longer be used to recover this account",
	})
}
