/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/cmd/server/errors.go
 * Tier: Server Entrypoint & HTTP Bootstrapper
 *
 * Description: Global Fiber ErrorHandler and HTTP status to error code mapping.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// statusToCode maps an HTTP status reaching the global ErrorHandler onto a
// machine-readable error code. Only 4xx statuses land here — 5xx is routed
// through httperr.SendInternal.
//
// The statuses Fiber raises itself (404 from the router, 405, 413, 415) have no
// constant in httperr because no handler produces them; they are spelled out as
// literals rather than collapsed into an existing constant, so a client never
// sees "invalid_request_body" for what was actually a routing miss.
func statusToCode(status int) httperr.Code {
	switch status {
	case fiber.StatusBadRequest:
		return httperr.CodeInvalidRequestBody
	case fiber.StatusUnauthorized:
		return httperr.CodeUnauthorized
	case fiber.StatusForbidden:
		return httperr.CodeForbidden
	case fiber.StatusNotFound:
		return httperr.CodeNotFound
	case fiber.StatusConflict:
		return httperr.CodeConflict
	case fiber.StatusUnprocessableEntity:
		return httperr.CodeValidationFailed
	case fiber.StatusTooManyRequests:
		return httperr.CodeRateLimited
	case fiber.StatusMethodNotAllowed:
		return "method_not_allowed"
	case fiber.StatusRequestEntityTooLarge:
		return "payload_too_large"
	case fiber.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	default:
		return "bad_request"
	}
}

// ErrorHandler is the last-resort handler for errors that reach Fiber unhandled: panics
// recovered by recover.New, router 404s, body-limit and parser failures.
//
// The body is the canonical flat {error, code} envelope and raw Go
// error text is logged rather than returned. That rule must hold:
// unhandled errors here carry panic messages and Ent/SQL failures
// naming tables and columns, and this handler answers callers who have
// not authenticated.
func ErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	// 5xx means something genuinely broke and the text is ours, not the
	// caller's — log it and return the generic body. SendInternal does
	// both, and forces the status to 500, which is already correct here.
	if code >= fiber.StatusInternalServerError {
		return httperr.SendInternal(c, "fiber.unhandled", err)
	}

	// 4xx is a client-shaped failure. *fiber.Error messages at this level
	// are Fiber's own static strings ("Not Found", "Method Not Allowed",
	// "Request Entity Too Large"), so they are safe to return — but only
	// for the *fiber.Error case. Any other error type reaching here with
	// a 4xx status is not a vetted string, so it gets the generic text.
	msg := "request could not be processed"
	if e, ok := err.(*fiber.Error); ok {
		msg = e.Message
	}
	return httperr.Send(c, code, statusToCode(code), msg)
}
