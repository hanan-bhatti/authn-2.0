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
	// CodeAccountDisabled means the credential was correct but the account is not
	// allowed to sign in: banned, suspended, or held after a recovery. Clients
	// branch on it to show a contact-support path rather than a retry prompt.
	CodeAccountDisabled Code = "account_disabled"

	// Authorization.
	CodeForbidden            Code = "forbidden"
	CodeInsufficientScope    Code = "insufficient_permissions"
	CodeTenantAdminRequired  Code = "tenant_admin_required"
	CodeImpersonationBlocked Code = "impersonation_blocked"

	// Tenant and origin binding. Both mean the credential is individually valid
	// but does not belong with the rest of the request: a session from another
	// tenant, or a browser origin the application never registered.
	CodeTenantMismatch   Code = "tenant_mismatch"
	CodeOriginNotAllowed Code = "origin_not_allowed"

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
// The two fields are not interchangeable: `error` is prose meant for a person
// and may be reworded at any time, while `code` is a stable identifier clients
// branch on. Swapping them forces consumers to substring-match across both.
type Envelope struct {
	// Error is the human-readable message. Never contains internal detail.
	Error string `json:"error"`
	// Code is the stable machine-readable identifier. Part of the wire contract.
	Code string `json:"code"`
}

// Send writes a canonical error response with the given HTTP status.
//
// msg must be safe to show a caller: no wrapped Go error text, no database
// driver output, no token parse detail. When holding an error value, use
// SendInternal for 5xx, or one of the 4xx helpers with a sanitized message.
func Send(c *fiber.Ctx, status int, code Code, msg string) error {
	return c.Status(status).JSON(Envelope{Error: msg, Code: string(code)})
}

// SendInternal logs err server-side and returns a generic 500 to the caller.
//
// Use it for every unexpected error that reaches a handler. Returning err
// directly would disclose ent and SQL driver text — including table and column
// names — to unauthenticated callers, so the detail stays in the log and the
// client receives a fixed message. op names the operation ("auth.login",
// "org.create") so the log line is actionable.
func SendInternal(c *fiber.Ctx, op string, err error) error {
	if err != nil {
		log.Printf("[error] %s %s %s: %v", c.Method(), c.Path(), op, err)
	}
	return Send(c, fiber.StatusInternalServerError, CodeInternal,
		"an internal error occurred while processing this request")
}

// Unauthorized answers 401: the caller is unauthenticated, or presented a
// credential that is missing, malformed or expired.
func Unauthorized(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusUnauthorized, code, msg)
}

// Forbidden answers 403: the caller is authenticated but not permitted to
// perform this operation. Re-authenticating will not help.
func Forbidden(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusForbidden, code, msg)
}

// NotFound answers 404: the addressed resource does not exist, or the caller
// may not know whether it does.
func NotFound(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusNotFound, code, msg)
}

// BadRequest answers 400: the request itself is malformed and will fail
// identically if retried unchanged.
func BadRequest(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusBadRequest, code, msg)
}

// Conflict answers 409: the request is well formed but collides with existing
// state, such as an email address already registered.
func Conflict(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusConflict, code, msg)
}

// UnprocessableEntity answers 422: the request parsed correctly but a value
// failed a semantic rule, such as a password below the configured policy.
func UnprocessableEntity(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusUnprocessableEntity, code, msg)
}

// TooManyRequests answers 429: the caller exceeded a rate limit and should
// retry after the period given in the Retry-After header.
func TooManyRequests(c *fiber.Ctx, code Code, msg string) error {
	return Send(c, fiber.StatusTooManyRequests, code, msg)
}

// InvalidBody answers 400 for a request body that is not valid JSON. Every
// handler calling c.BodyParser needs this exact response, so it is spelled once.
func InvalidBody(c *fiber.Ctx) error {
	return BadRequest(c, CodeInvalidRequestBody, "request body is not valid JSON")
}
