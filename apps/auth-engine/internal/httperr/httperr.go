/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/httperr/httperr.go
 * Tier: HTTP Transport Layer / Error Envelope
 *
 * Description: Canonical error-response envelope for every HTTP handler. Guarantees a
 *              stable machine-readable `code` on every error body and keeps internal
 *              error text (database driver output, JWT parse failures, wrapped Go
 *              errors) server-side instead of returning it to callers.
 *
 * Audit: M9 (inconsistent envelopes, err.Error() leaked to clients), H8 (sentinel
 *        comparison), and the SDK's AuthnError.fromResponse contract.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package httperr

import (
	"log"

	"github.com/gofiber/fiber/v2"
)

// Code is a stable, machine-readable error identifier returned as the `code`
// field of every error body. The SDK's mapHttpStatusToCode matches on these, so
// values here are a wire contract: renaming one is a breaking API change.
type Code string

const (
	// Request shape and validation.
	CodeInvalidRequestBody Code = "invalid_request_body"
	CodeValidationFailed   Code = "validation_failed"
	CodeMissingParameter   Code = "missing_parameter"

	// Authentication.
	CodeUnauthorized              Code = "unauthorized"
	CodeInvalidCredentials        Code = "invalid_credentials"
	CodeSessionExpired            Code = "session_expired"
	CodeInvalidToken              Code = "invalid_token"
	CodeEmailVerificationRequired Code = "email_verification_required"
	CodeMagicLinkExpired          Code = "magic_link_expired"
	CodeMFARequired               Code = "mfa_required"
	CodeInvalidMFACode            Code = "invalid_mfa_code"

	// Authorization.
	CodeForbidden            Code = "forbidden"
	CodeInsufficientScope    Code = "insufficient_permissions"
	CodeTenantAdminRequired  Code = "tenant_admin_required"
	CodeImpersonationBlocked Code = "impersonation_blocked"

	// Resource state.
	CodeNotFound      Code = "not_found"
	CodeAlreadyExists Code = "already_exists"
	CodeConflict      Code = "conflict"

	// Throttling and availability.
	CodeRateLimited        Code = "rate_limited"
	CodeServiceUnavailable Code = "service_unavailable"

	// Catch-all. Never carries internal detail to the client.
	CodeInternal Code = "internal_error"
)

// Envelope is the canonical error body. Every error response in the engine
// serializes to exactly this shape:
//
//	{"error": "human readable prose", "code": "machine_readable_code"}
//
// `error` is the human-facing message and `code` is what clients branch on.
// Note the two are NOT interchangeable — a handful of legacy sites had these
// inverted (code in `error`, prose in `message`), which is precisely why the
// SDK had to substring-match across both fields.
type Envelope struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// Send writes a canonical error response with the given HTTP status.
//
// msg must be safe to show a caller: no wrapped Go error text, no database
// driver output, no token parse detail. When you are holding an error value,
// use SendInternal (5xx) or Sendf (4xx with a sanitized message) instead.
func Send(c *fiber.Ctx, status int, code Code, msg string) error {
	return c.Status(status).JSON(Envelope{Error: msg, Code: string(code)})
}

// SendInternal logs err server-side and returns a generic 500 to the caller.
//
// This is the one function that must be used whenever an unexpected error
// reaches a handler. Roughly 160 sites previously passed err.Error() straight
// into the response body, leaking ent/SQL driver text — including table and
// column names — to unauthenticated callers. op should identify the operation
// ("auth.login", "org.create") so the log line is actionable.
func SendInternal(c *fiber.Ctx, op string, err error) error {
	if err != nil {
		log.Printf("[error] %s %s %s: %v", c.Method(), c.Path(), op, err)
	}
	return Send(c, fiber.StatusInternalServerError, CodeInternal,
		"an internal error occurred while processing this request")
}

// Unauthorized, Forbidden, NotFound, BadRequest and Conflict are the common
// 4xx shortcuts. Each takes an explicit client-safe message so call sites keep
// their specific wording without hand-building a fiber.Map.

func Unauthorized(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusUnauthorized, code, msg)
}

func Forbidden(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusForbidden, code, msg)
}

func NotFound(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusNotFound, code, msg)
}

func BadRequest(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusBadRequest, code, msg)
}

func Conflict(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusConflict, code, msg)
}

func UnprocessableEntity(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusUnprocessableEntity, code, msg)
}

func TooManyRequests(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusTooManyRequests, code, msg)
}

// InvalidBody is the single most repeated error in the codebase — every handler
// that calls c.BodyParser needs it.
func InvalidBody(c *fiber.Ctx) error {
	return BadRequest(c, CodeInvalidRequestBody, "request body is not valid JSON")
}
