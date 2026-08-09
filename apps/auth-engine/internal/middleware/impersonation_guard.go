/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/impersonation_guard.go
 * Tier: HTTP Middleware Layer / Impersonation Read-Only Guard
 *
 * Read-only enforcement for admin impersonation sessions (FR-14).
 *
 * An impersonation token carries the target user's identity but belongs to a
 * support agent, so it must be able to observe an account without being able to
 * take it over. This middleware refuses the destructive end-user mutations —
 * credential changes, two-factor teardown, account deletion, recovery — for any
 * session whose token is marked impersonated, and leaves every other route
 * untouched.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// destructiveRoute is one (method, path) pattern that mutates security-sensitive
// account state and is refused during impersonation.
type destructiveRoute struct {
	// method is the exact HTTP method, uppercase.
	method string
	// suffix is the tail of the route path. It is compared case-insensitively
	// against the request path with any trailing slash removed.
	suffix string
	// hasParamTail marks a route whose real path ends in a variable segment
	// (/credentials/:id, /social-accounts/:provider). The request path must then
	// contain suffix+"/" rather than end with suffix.
	hasParamTail bool
}

// impersonationDenyList is the complete inventory of destructive end-user
// mutations under /v1/client, enumerated one route at a time.
//
// The enumeration is the invariant. Matching a path by substring ("does it
// contain /2fa") is simultaneously too broad and too narrow: it captures
// read-only routes that merely share a word, and it misses the real destructive
// path whenever the segment is spelled differently than assumed. An explicit
// list is auditable — every entry corresponds to a route registered in the auth
// and user handlers, and the list is exactly the set of blocked operations.
//
// A new destructive end-user route MUST be added here when it is registered. A
// read-only route MUST NOT appear.
var impersonationDenyList = []destructiveRoute{
	// Account lifecycle.
	{method: "DELETE", suffix: "/user/account"},

	// Credentials and contact addresses.
	{method: "POST", suffix: "/user/password"},
	{method: "POST", suffix: "/user/email"},
	{method: "POST", suffix: "/user/recovery-email"},
	{method: "DELETE", suffix: "/user/recovery-email"},
	{method: "DELETE", suffix: "/user/social-accounts", hasParamTail: true},

	// Two-factor teardown and re-enrollment.
	{method: "POST", suffix: "/2fa/totp/disable"},
	{method: "POST", suffix: "/2fa/totp/enroll"},
	{method: "POST", suffix: "/2fa/sms/enroll"},
	{method: "DELETE", suffix: "/2fa/sms/disable"},
	{method: "POST", suffix: "/2fa/recovery-codes/regenerate"},
	{method: "DELETE", suffix: "/2fa/webauthn/credentials", hasParamTail: true},

	// Guardians — the social contacts who can vouch for an account recovery.
	{method: "POST", suffix: "/account/guardians/invite"},
	{method: "DELETE", suffix: "/account/guardians", hasParamTail: true},

	// Recovery. Initiating or claiming a recovery is a takeover vector, so an
	// impersonated session must not be able to drive either half.
	{method: "POST", suffix: "/auth/recovery/initiate"},
	{method: "POST", suffix: "/auth/recovery/claim"},
}

// matchesDestructiveRoute reports whether (method, path) names a destructive
// end-user mutation listed in impersonationDenyList. Method comparison is exact
// after uppercasing; path comparison is case-insensitive and ignores a single
// trailing slash.
func matchesDestructiveRoute(method, path string) bool {
	method = strings.ToUpper(method)
	path = strings.ToLower(strings.TrimRight(path, "/"))

	for _, r := range impersonationDenyList {
		if method != r.method {
			continue
		}
		suffix := strings.ToLower(r.suffix)
		if r.hasParamTail {
			if strings.Contains(path, suffix+"/") {
				return true
			}
			continue
		}
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// tokenFailureReason maps a VerifyAccessToken error onto one of a fixed set of
// log labels: "malformed", "bad_signature", "expired", "undecodable_payload",
// "unparseable_claims", "nil_claims", or "verification_failed" for anything else.
//
// It returns a label rather than err.Error() because two of the verifier's paths
// wrap a lower-level error — base64 decode, json.Unmarshal — whose text can
// quote a fragment of the decoded token payload; a json.SyntaxError renders the
// offending character. A closed label set guarantees no token material reaches
// the log through this path whatever the wrapped error holds, and keeps the
// field aggregatable. An unrecognised error collapses to "verification_failed",
// so a new error string upstream cannot start leaking token bytes here.
func tokenFailureReason(err error) string {
	if err == nil {
		return "nil_claims"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "invalid jwt format"):
		return "malformed"
	case strings.Contains(msg, "invalid jwt signature"):
		return "bad_signature"
	case strings.Contains(msg, "has expired"):
		return "expired"
	case strings.Contains(msg, "failed decoding jwt payload"):
		return "undecodable_payload"
	case strings.Contains(msg, "failed unmarshaling jwt claims"):
		return "unparseable_claims"
	default:
		return "verification_failed"
	}
}

// PreventImpersonatedMutations returns a Fiber middleware that answers 403 to a
// destructive account mutation whenever the caller's access token is marked
// impersonated. Every other request continues down the chain unchanged.
// signingSecret verifies the access-token signature.
//
// Token extraction goes through extractAccessToken, so this guard applies the
// same cookie-then-header precedence as RequireClientAuth. The two MUST agree: a
// guard that reads only the Authorization header sees no credential at all on a
// cookie-authenticated session, waves the request through, and RequireClientAuth
// then admits it from the cookie — the restriction vanishes for precisely the
// browser sessions it exists to constrain.
//
// The guard fails open on a token it cannot verify, and records that it did.
// It is an additional restriction layered ahead of RequireClientAuth, which runs
// downstream and is what actually rejects a bad token; rejecting here would
// return the wrong status from the wrong layer. Fail-open is only safe while it
// is observable, hence the log line on every skip.
func PreventImpersonatedMutations(signingSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenStr := extractAccessToken(c)
		if strings.TrimSpace(tokenStr) == "" {
			// No credential is the normal case for the unauthenticated half of
			// /v1/client (login, signup, password reset). It carries no signal and
			// is not logged; the branch below is the one worth recording, because
			// there a token was presented and could not be verified.
			return c.Next()
		}

		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil || claims == nil {
			log.Printf("[warn] impersonation guard skipped: token failed verification (reason=%s) %s %s",
				tokenFailureReason(err), c.Method(), c.Path())
			return c.Next()
		}

		if claims.IsImpersonated && matchesDestructiveRoute(c.Method(), c.Path()) {
			// This code string is a published wire contract
			// (docs/03-API-SPECIFICATION.md, docs/14-USER-IMPERSONATION.md) and is
			// deliberately not the generic httperr.CodeImpersonationBlocked.
			return httperr.Send(c, fiber.StatusForbidden, "impersonation_read_only_restricted",
				"destructive account mutation is disabled during an active impersonation session: read-only security mode active")
		}

		return c.Next()
	}
}
