/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/middleware/admin_auth.go
 * Tier: HTTP Middleware Layer / Admin Authentication
 *
 * Unified authentication for the admin surface (/v1/tenant/*, /v1/admin/*).
 *
 * Two kinds of caller reach these routes: backend servers holding an sk_ secret
 * key, and the Authn web console, which signs its operator in through the normal
 * end-user login and presents the resulting JWT. Both are accepted here, in one
 * middleware, and the credential kind is decided from the raw header value
 * before anything is written to the response — chaining two middlewares instead
 * would let the first write a 401 that the second could no longer take back.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package middleware

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

const (
	// EnvironmentTest is the environment an unresolved request falls back to, so a
	// routing or configuration mistake lands in the sandbox rather than in live.
	EnvironmentTest = "test"
	// EnvironmentLive is the environment serving a tenant's real customers.
	EnvironmentLive = "live"
)

// Primary2FAValidator reports how many active primary second factors a user has
// enrolled. It is an interface so this package does not depend on the MFA
// package, which depends on this one.
type Primary2FAValidator interface {
	// CountActivePrimary2FAMethods returns the number of enrolled, active
	// primary second factors (TOTP, passkey) for userID.
	CountActivePrimary2FAMethods(ctx context.Context, userID string) (int, error)
}

// RequireAdminAuth returns a Fiber middleware gating admin routes behind either
// a valid sk_ secret key or a JWT access token carrying role=tenant_admin. The
// credential is read from X-Authn-Secret-Key, falling back to Authorization:
// Bearer, and dispatched on its prefix — "sk_" for a secret key, "eyJ" for the
// base64url JSON header of a JWT.
//
// signingSecret verifies console tokens. bl is consulted for console tokens
// only: a secret key is checked against storage on every request, so its
// revocation is already immediate, while a JWT is self-contained and would
// otherwise stay valid for its full lifetime after a sign-out, an impersonation
// exit, or a ban. An optional validator, when supplied, additionally refuses
// console operators who have not enrolled a second factor: an administrator's
// password alone must not command the admin surface.
//
// It answers 401 for a missing, unrecognised, or invalid credential, and 403 for
// a valid end-user token that lacks the tenant_admin role or the required 2FA
// enrolment. On success it installs the resolved tenant and environment on the
// privacy context and records which of the two routes authenticated the caller
// in the admin_auth_method local.
func RequireAdminAuth(apiKeyService *apikey.Service, signingSecret string, bl *tokenblocklist.Blocklist, validator ...Primary2FAValidator) fiber.Handler {
	var v Primary2FAValidator
	if len(validator) > 0 {
		v = validator[0]
	}

	return func(c *fiber.Ctx) error {
		if guardCompleted(c, guardAdminAuth) {
			return c.Next()
		}

		raw := strings.TrimSpace(c.Get("X-Authn-Secret-Key"))
		if raw == "" {
			authHeader := c.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				raw = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			}
		}

		if raw == "" {
			return httperr.Unauthorized(c, httperr.CodeUnauthorized,
				"admin authentication required: provide Authorization: Bearer sk_... (backend) or Bearer <jwt> with tenant_admin role (console)")
		}

		// Backend server / SDK: sk_ secret key.
		if strings.HasPrefix(raw, "sk_") {
			key, app, err := apiKeyService.ValidateKey(c.UserContext(), raw, apikey.TypeSecret)
			if err != nil {
				return httperr.Unauthorized(c, httperr.CodeUnauthorized,
					"invalid, expired, or revoked secret key")
			}
			envStr := string(key.Environment)
			privacyCtx := privacy.NewContext(c.UserContext(), app.TenantID, app.ID, envStr)
			c.SetUserContext(privacyCtx)
			c.Locals("tenant_id", app.TenantID)
			c.Locals("application_id", app.ID)
			c.Locals("environment", envStr)
			c.Locals("api_key_id", key.ID)
			c.Locals("admin_auth_method", "secret_key")
			markGuardCompleted(c, guardAdminAuth)
			return c.Next()
		}

		// Web console: JWT access token from the normal login flow.
		if strings.HasPrefix(raw, "eyJ") {
			claims, err := jwtpkg.VerifyAccessToken(raw, signingSecret)
			if err != nil {
				return httperr.Unauthorized(c, httperr.CodeInvalidToken,
					"invalid or expired console session token")
			}

			if bl.IsBlocked(c.UserContext(), claims.Jti) {
				return httperr.Unauthorized(c, httperr.CodeInvalidToken,
					"this console session has been revoked: sign in again")
			}

			if bl.IsUserTokenRefused(c.UserContext(), claims.Sub, claims.Iat) {
				return httperr.Forbidden(c, httperr.CodeAccountDisabled,
					"this account is no longer permitted to administer this tenant")
			}

			// A key middleware may have resolved a tenant ahead of this one. When
			// it did, the console token must agree with it — see the same check in
			// RequireClientAuth for why a token's tenant is not trusted alone.
			if keyTenant := GetTenantID(c); keyTenant != "" && keyTenant != claims.TenantID {
				return httperr.Unauthorized(c, httperr.CodeTenantMismatch,
					"this console session belongs to a different tenant than the API key used for this request — "+
						"sign in again as an administrator of this tenant")
			}

			if claims.Role != "tenant_admin" {
				return httperr.Forbidden(c, httperr.CodeTenantAdminRequired,
					"forbidden: tenant_admin role required — regular user JWTs cannot access admin routes")
			}

			if v != nil {
				count, err := v.CountActivePrimary2FAMethods(c.UserContext(), claims.Sub)
				// A validator error leaves the operator through: the second factor
				// is enforced on a known-zero count, not on an unknown one, so a
				// database blip cannot lock every administrator out of the console.
				if err == nil && count == 0 {
					// The enrolment path travels in the prose because the envelope
					// is flat. The admin_2fa_required code is what the console
					// branches on to redirect into enrolment.
					return httperr.Forbidden(c, "admin_2fa_required",
						"admin 2FA required: administrator accounts must enroll in 2FA (TOTP or Passkey) at /v1/client/auth/2fa/totp/enroll before accessing admin features")
				}
			}

			privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, "", claims.Environment)
			c.SetUserContext(privacyCtx)
			c.Locals("tenant_id", claims.TenantID)
			c.Locals("environment", claims.Environment)
			c.Locals("console_user_id", claims.Sub)
			c.Locals("console_user_email", claims.Email)
			c.Locals("admin_auth_method", "console_jwt")
			markGuardCompleted(c, guardAdminAuth)
			return c.Next()
		}

		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"unrecognised credential format: expected sk_... secret key or eyJ... JWT access token")
	}
}

// GetTenantID returns the tenant resolved by whichever auth middleware ran, or
// "" when none was resolved.
//
// There is deliberately no default tenant: every route using this sits behind a
// middleware that sets the tenant on success and rejects the request otherwise,
// so an empty value means the request was never authenticated. Substituting one
// would turn a middleware misconfiguration into a cross-tenant read or write.
func GetTenantID(c *fiber.Ctx) string {
	if val, ok := c.Locals("tenant_id").(string); ok && val != "" {
		return val
	}
	return ""
}

// RequireTenantID returns the authenticated caller's tenant, or answers 401 and
// reports false. A caller that gets false must return nil without writing
// anything further: the response is already sent, and a second answer would
// replace it with whatever the global error handler makes of it.
//
// Handlers must take the tenant from here rather than from the query string, a
// path parameter or the request body. The tenant decides which rows the request
// reaches, so accepting a caller-supplied value lets anyone holding a valid
// credential for one tenant address every other tenant by naming it. Reporting
// false on an empty value keeps a routing mistake a 401 instead of a
// cross-tenant read or write against a fallback tenant.
func RequireTenantID(c *fiber.Ctx) (string, bool) {
	if tenantID := GetTenantID(c); tenantID != "" {
		return tenantID, true
	}
	_ = httperr.Unauthorized(c, httperr.CodeUnauthorized,
		"tenant could not be resolved from the supplied credential")
	return "", false
}

// GetEnvironment returns the environment resolved by whichever auth middleware
// ran, defaulting to "test".
//
// The environment is a property of the credential — a test key addresses test
// data and a live key live data — so it is read from here rather than from the
// request. Defaulting to "test" keeps an unresolved request away from live rows.
func GetEnvironment(c *fiber.Ctx) string {
	if val, ok := c.Locals("environment").(string); ok && val != "" {
		return val
	}
	return EnvironmentTest
}

// RequireLiveKey is a middleware that refuses a request whose credential
// addresses the test environment.
//
// It guards configuration that has no test counterpart and governs live traffic
// regardless of which key wrote it. A webhook endpoint is the case: there is one
// list per tenant and the dispatcher delivers to all of it, so a test key
// repointing or deleting an entry would change where a live event lands. Holding
// that behind the live key keeps the reach of a test key inside test.
//
// Reads are deliberately left open, matching the settings publish rule: seeing
// the other environment's configuration crosses nothing, changing it does.
func RequireLiveKey(c *fiber.Ctx) error {
	if GetEnvironment(c) == EnvironmentLive {
		return c.Next()
	}
	return httperr.Forbidden(c, httperr.CodeLiveKeyRequired,
		"this configuration governs the live environment and can only be changed with a live key")
}
