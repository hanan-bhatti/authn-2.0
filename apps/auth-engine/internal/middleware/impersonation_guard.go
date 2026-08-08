/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/impersonation_guard.go
 * Tier: HTTP Delivery Layer / Security Middleware
 *
 * Description: Prevents destructive account mutations (password reset, 2FA removal,
 *              account deletion) during active admin impersonation sessions (FR-14).
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

// destructiveRoute names a single (method, path-suffix) pair that mutates
// security-sensitive account state and must be blocked while a session is
// impersonated. The suffix is matched against the request path with HasSuffix
// after trailing-slash normalization, so a param segment like ":id" is written
// here as the literal prefix it shares — see matchesDestructiveRoute.
type destructiveRoute struct {
	method string
	// suffix is compared with strings.HasSuffix against the normalized path.
	// hasParamTail, when true, means the real route ends in a variable segment
	// (e.g. /credentials/:id or /social-accounts/:provider); we then require the
	// path to CONTAIN suffix+"/" rather than end with suffix.
	suffix       string
	hasParamTail bool
}

// impersonationDenyList is the explicit, auditable inventory of destructive
// end-user mutations under /v1/client. It replaces the previous substring
// matching (strings.Contains(path, "/2fa")), which was simultaneously too broad
// (it would have blocked any future read route containing "/2fa") and too narrow
// (it matched "/2fa/disable", a path that does not exist, while missing the real
// "/2fa/totp/disable" — audit finding H7).
//
// Every entry corresponds to a route actually registered in the auth/user
// handlers. When a new destructive end-user route is added, it MUST be listed
// here as well; a read-only route must never appear.
var impersonationDenyList = []destructiveRoute{
	// Account lifecycle
	{method: "DELETE", suffix: "/user/account"},

	// Credentials
	{method: "POST", suffix: "/user/password"},
	{method: "POST", suffix: "/user/email"},
	{method: "POST", suffix: "/user/recovery-email"},
	{method: "DELETE", suffix: "/user/recovery-email"},
	{method: "DELETE", suffix: "/user/social-accounts", hasParamTail: true},

	// Two-factor authentication teardown / re-enrollment
	{method: "POST", suffix: "/2fa/totp/disable"},
	{method: "POST", suffix: "/2fa/totp/enroll"},
	{method: "POST", suffix: "/2fa/sms/enroll"},
	{method: "DELETE", suffix: "/2fa/sms/disable"},
	{method: "POST", suffix: "/2fa/recovery-codes/regenerate"},
	{method: "DELETE", suffix: "/2fa/webauthn/credentials", hasParamTail: true},

	// Social account recovery contacts (guardians)
	{method: "POST", suffix: "/account/guardians/invite"},
	{method: "DELETE", suffix: "/account/guardians", hasParamTail: true},

	// Account recovery: initiating or claiming a recovery is a takeover vector;
	// an impersonated session must not be able to drive it.
	{method: "POST", suffix: "/auth/recovery/initiate"},
	{method: "POST", suffix: "/auth/recovery/claim"},
}

// matchesDestructiveRoute reports whether the request (method, path) is a
// destructive end-user mutation per impersonationDenyList. Path comparison is
// case-insensitive and ignores a single trailing slash.
func matchesDestructiveRoute(method, path string) bool {
	method = strings.ToUpper(method)
	path = strings.ToLower(strings.TrimRight(path, "/"))

	for _, r := range impersonationDenyList {
		if method != r.method {
			continue
		}
		suffix := strings.ToLower(r.suffix)
		if r.hasParamTail {
			// Route ends in a variable segment: match "<suffix>/<something>".
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

// tokenFailureReason maps a VerifyAccessToken error onto a small, fixed set of
// log labels.
//
// It deliberately does NOT return err.Error(). Two of the verifier's error paths
// wrap a lower-level error (base64 decode, json.Unmarshal) whose text can quote a
// fragment of the decoded token payload — json.SyntaxError, for example, renders
// the offending character. Emitting a stable label instead guarantees that no
// token material can ever reach the log through this path, no matter what the
// wrapped error contains, and it keeps the field aggregatable.
//
// Anything unrecognised collapses to "verification_failed" rather than falling
// through to the raw error, so adding a new error string upstream cannot silently
// start leaking token bytes here.
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

// PreventImpersonatedMutations blocks destructive mutations when claims.IsImpersonated == true.
func PreventImpersonatedMutations(signingSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Resolve the token exactly as RequireClientAuth does — cookie first,
		// then Authorization header. Reading only the header (the previous
		// behavior) let a cookie-authed impersonation session bypass the guard
		// entirely (audit finding H6).
		tokenStr := extractAccessToken(c)
		if strings.TrimSpace(tokenStr) == "" {
			// No credential at all is the normal case for the unauthenticated
			// half of /v1/client (login, signup, password reset), so this path
			// is intentionally NOT logged — it would drown the log in noise and
			// carries no signal. The branch below is different: a token was
			// presented and could not be verified.
			return c.Next()
		}

		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil || claims == nil {
			// Fail-open is deliberate and load-bearing: this guard is an extra
			// restriction layered on top of RequireClientAuth, which runs
			// downstream and is what actually rejects a bad token. Blocking here
			// would turn every malformed token into a 403 from the wrong layer.
			//
			// But fail-open twice over and silently is how a guard rots unnoticed
			// (audit finding M8). Record that the guard declined to evaluate, with
			// enough context to spot a pattern — never the token itself, and never
			// the raw error (see tokenFailureReason).
			log.Printf("[warn] impersonation guard skipped: token failed verification (reason=%s) %s %s",
				tokenFailureReason(err), c.Method(), c.Path())
			return c.Next()
		}

		if claims.IsImpersonated && matchesDestructiveRoute(c.Method(), c.Path()) {
			// NOTE: the code string here is the documented wire contract
			// (docs/03-API-SPECIFICATION.md, docs/14-USER-IMPERSONATION.md) and is
			// deliberately NOT swapped for httperr.CodeImpersonationBlocked —
			// renaming it would break published clients. Only the envelope shape
			// is normalized (audit finding M9).
			return httperr.Send(c, fiber.StatusForbidden, "impersonation_read_only_restricted",
				"destructive account mutation is disabled during an active impersonation session: read-only security mode active")
		}

		return c.Next()
	}
}
