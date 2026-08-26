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

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// securityQuestionStepUp names the change in the step-up messages.
//
// Security questions are the one recovery factor a caller can enroll entirely on its
// own. A guardian has to accept an invitation from their own mailbox and a recovery
// address has to be confirmed from that address, so neither can be planted by whoever
// is merely holding a session. Answers only need to be typed, which makes an unattended
// session enough to install a permanent way back into the account — one that survives a
// password change and a full session revocation, because recovery is designed to survive
// exactly those.
const securityQuestionStepUp = "change your security questions"

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
		// checked on is read; see stepUpCredential.
		Password string `json:"password,omitempty"`
		TOTPCode string `json:"totp_code,omitempty"`
	}
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if !h.stepUpCredential(c, userID, req.Password, req.TOTPCode, securityQuestionStepUp) {
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

	if !h.stepUpCredential(c, userID, req.Password, req.TOTPCode, securityQuestionStepUp) {
		return nil
	}

	if err := h.recoveryService.DeleteSecurityQuestions(c.UserContext(), userID); err != nil {
		return httperr.SendInternal(c, "auth.security_questions.delete", err)
	}

	return c.JSON(fiber.Map{
		"message": "security questions removed: they can no longer be used to recover this account",
	})
}
