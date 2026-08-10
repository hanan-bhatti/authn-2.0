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
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
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
// signingSecret verifies console tokens. An optional validator, when supplied,
// additionally refuses console operators who have not enrolled a second factor:
// an administrator's password alone must not command the admin surface.
//
// It answers 401 for a missing, unrecognised, or invalid credential, and 403 for
// a valid end-user token that lacks the tenant_admin role or the required 2FA
// enrolment. On success it installs the resolved tenant and environment on the
// privacy context and records which of the two routes authenticated the caller
// in the admin_auth_method local.
func RequireAdminAuth(apiKeyService *apikey.Service, signingSecret string, validator ...Primary2FAValidator) fiber.Handler {
	var v Primary2FAValidator
	if len(validator) > 0 {
		v = validator[0]
	}

	return func(c *fiber.Ctx) error {
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
			return c.Next()
		}

		// Web console: JWT access token from the normal login flow.
		if strings.HasPrefix(raw, "eyJ") {
			claims, err := jwtpkg.VerifyAccessToken(raw, signingSecret)
			if err != nil {
				return httperr.Unauthorized(c, httperr.CodeInvalidToken,
					"invalid or expired console session token")
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
						"admin 2FA required: administrator accounts must enroll in 2FA (TOTP or Passkey) at /v1/client/2fa/totp/enroll before accessing admin features")
				}
			}

			privacyCtx := privacy.NewContext(c.UserContext(), claims.TenantID, "", claims.Environment)
			c.SetUserContext(privacyCtx)
			c.Locals("tenant_id", claims.TenantID)
			c.Locals("environment", claims.Environment)
			c.Locals("console_user_id", claims.Sub)
			c.Locals("console_user_email", claims.Email)
			c.Locals("admin_auth_method", "console_jwt")
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
