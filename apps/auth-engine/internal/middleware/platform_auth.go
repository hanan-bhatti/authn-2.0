/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/platform_auth.go
 * Tier: HTTP Middleware Layer / Platform Control-Plane Authentication
 *
 * Authentication for the hosted control plane (/v1/platform/*).
 *
 * The control plane is a tenant of itself: a reserved platform tenant whose end
 * users are the SaaS customers who go on to provision tenants of their own. They
 * sign in through the ordinary auth stack — signup, 2FA, sessions — so the
 * credential on these routes is an end-user JWT belonging to that one tenant.
 * Never an API key, and never a token issued for any other tenant.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// PlatformAccountLookup resolves the account a platform token names.
//
// It is an interface so this package does not depend on the auth package, which
// depends on this one.
type PlatformAccountLookup interface {
	// EmailVerified reports whether userID's email address is verified, and
	// whether the account exists at all.
	//
	// Both answers are needed. A token naming an account that no longer exists
	// and a token naming one that never finished signing up are different
	// conditions with different remedies, so folding either into the other would
	// report the wrong status for it.
	EmailVerified(ctx context.Context, userID string) (verified bool, found bool, err error)
}

// RequirePlatformAuth returns a Fiber middleware gating the hosted control plane
// behind an end-user JWT issued for the platform tenant.
//
// It deliberately does not reuse RequireAdminAuth. That guard demands
// role=tenant_admin, and the first-admin slot is single-shot per tenant, so on
// the platform tenant exactly one human on the whole deployment would ever
// qualify — self-serve signup would be dead on arrival. Membership of the
// platform tenant is the credential here instead.
//
// Which makes the tenant check authentication rather than authorization: the
// platform tenant's publishable key ships in the console's browser bundle, so
// anyone can sign up into it. That is the point of self-serve, and it is why
// lookup is consulted for a verified email address — otherwise an address the
// caller does not control would be enough to reach the control plane. Callers
// must additionally rate-limit per user; this guard admits, it does not meter.
//
// The checks in order, each answering before the next runs:
//
//   - 404 when platformTenantID is empty. A deployment that hosts no control
//     plane should not disclose that the route exists. Registration is normally
//     skipped entirely in that case, so this is the backstop for a miswiring.
//   - 503 when lookup is nil, for the same reason: the verified-email check is
//     not optional, so a guard that cannot perform it refuses everything.
//   - 401 for an API key in any position. A pk_ is public, and an sk_ carries a
//     tenant's whole admin surface; neither establishes which human is asking,
//     and provisioning has to attribute ownership to a person.
//   - 401 for a missing, unverifiable, or revoked token.
//   - 403 for an impersonated token, else an operator's read-only support
//     session over a customer's account becomes a tenant-minting credential.
//   - 403 when the token's tenant is not the platform tenant.
//   - 403 when the account's email address is unverified, 401 when the account
//     is gone, 503 when the lookup itself fails.
//
// On success the platform tenant goes onto the privacy context, scoping every
// downstream ORM query to the control plane, and the caller's identity onto the
// request locals. Handlers must read the tenant from there and never from the
// request.
func RequirePlatformAuth(signingSecret, platformTenantID string, bl *tokenblocklist.Blocklist, lookup PlatformAccountLookup) fiber.Handler {
	platformTenantID = strings.TrimSpace(platformTenantID)

	return func(c *fiber.Ctx) error {
		if platformTenantID == "" {
			return httperr.NotFound(c, httperr.CodeNotFound, "resource not found")
		}

		// A guard that cannot check for a verified address must not admit anyone.
		// The platform tenant's publishable key is public, so that check is the
		// only thing between an arbitrary signup and the control plane; failing
		// closed makes a wiring mistake an outage rather than an open door.
		if lookup == nil {
			return httperr.Send(c, fiber.StatusServiceUnavailable, httperr.CodeServiceUnavailable,
				"the platform control plane is not available")
		}

		// An API key presented in its own header is refused before the token is
		// even read: a request carrying one is asking to authenticate as a
		// machine, and this surface has no machine callers.
		if strings.TrimSpace(c.Get("X-Authn-Secret-Key")) != "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"the platform control plane does not accept API keys: sign in and present Authorization: Bearer <jwt>")
		}

		tokenStr := ExtractAccessToken(c)
		if strings.HasPrefix(tokenStr, "sk_") || strings.HasPrefix(tokenStr, "pk_") {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"the platform control plane does not accept API keys: sign in and present Authorization: Bearer <jwt>")
		}
		if strings.TrimSpace(tokenStr) == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"platform session required: provide Authorization: Bearer <jwt> or the authn_access_token cookie")
		}

		claims, err := jwtpkg.VerifyAccessToken(tokenStr, signingSecret)
		if err != nil || claims == nil {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"invalid or expired platform session token")
		}

		// A JTI revoked before its natural expiry — sign-out, impersonation exit,
		// a forced logout — must not still command the control plane.
		if bl.IsBlocked(c.UserContext(), claims.Jti) {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"this platform session has been revoked: sign in again")
		}

		// A platform operator whose account was restricted loses the control plane
		// on the next request rather than at the end of the token's lifetime. The
		// stakes here are higher than on the client tier, not lower.
		if bl.IsUserTokenRefused(c.UserContext(), claims.Sub, claims.Iat) {
			return httperr.Forbidden(c, httperr.CodeAccountDisabled,
				"this account is no longer permitted to access the platform control plane")
		}

		if claims.IsImpersonated {
			return httperr.Forbidden(c, httperr.CodeImpersonationBlocked,
				"the platform control plane is unreachable during an impersonation session")
		}

		if claims.TenantID != platformTenantID {
			return httperr.Forbidden(c, httperr.CodeTenantMismatch,
				"this session does not belong to the platform control plane")
		}

		if strings.TrimSpace(claims.Sub) == "" {
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"platform session token names no subject")
		}

		// The scope is installed from the configured tenant rather than from the
		// claim it was just compared against. The two are equal here by
		// construction; taking the configured value means a future edit to the
		// comparison above cannot widen a request's reach past the control plane.
		privacyCtx := privacy.NewContext(c.UserContext(), platformTenantID, "", claims.Environment)
		c.SetUserContext(privacyCtx)

		// The lookup runs after the scope is installed, so it reads the platform
		// tenant's own user rows and cannot be answered by a same-numbered row
		// belonging to some other tenant.
		verified, found, err := lookup.EmailVerified(privacyCtx, claims.Sub)
		switch {
		case err != nil:
			// Fail closed, unlike the 2FA validator in RequireAdminAuth. That one
			// leaves an operator through on a database blip because locking every
			// administrator out of the console is the worse outcome. Here the
			// guarded operations write to the same database that just failed, so
			// admitting the request buys nothing and would let an unverified
			// address through precisely when the check cannot see it.
			return httperr.Send(c, fiber.StatusServiceUnavailable, httperr.CodeServiceUnavailable,
				"platform account could not be verified: please retry")
		case !found:
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"this platform session names an account that no longer exists")
		case !verified:
			return httperr.Forbidden(c, httperr.CodeEmailVerificationRequired,
				"verify your email address before using the platform control plane")
		}

		c.Locals("tenant_id", platformTenantID)
		c.Locals("environment", claims.Environment)
		c.Locals("platform_user_id", claims.Sub)
		c.Locals("platform_user_email", claims.Email)

		return c.Next()
	}
}

// PlatformUserID returns the platform-tenant user resolved by
// RequirePlatformAuth, or "" when the guard did not run.
//
// Ownership of a provisioned tenant is attributed to this value, so a handler
// must never accept a user identifier from the request in its place.
func PlatformUserID(c *fiber.Ctx) string {
	if val, ok := c.Locals("platform_user_id").(string); ok {
		return val
	}
	return ""
}
