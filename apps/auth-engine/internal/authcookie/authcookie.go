/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/authcookie/authcookie.go
 * Tier: Delivery Layer / Session Cookie Construction
 *
 * The one place session cookies are built.
 *
 * Every handler that issues a session goes through here, so HTTPOnly, Secure,
 * SameSite and Path are decided once. Path matters most: two endpoints consume the
 * refresh cookie, and a cookie scoped to only one of their prefixes is simply never
 * sent to the other, leaving a browser holding a cookie it cannot use.
 *
 * Every attribute comes from one of two inputs:
 *
 *   - the tenant's session policy for the environment being signed into, read from
 *     the database, for SameSite and lifetimes, because a customer changes those and
 *     must not wait for a deploy
 *   - the deployment's own configuration, for Secure and Domain, because those are
 *     facts about where the server runs rather than customer preferences
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package authcookie

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

const (
	// RefreshTokenName is the cookie carrying the rotating refresh token.
	RefreshTokenName = "authn_refresh_token"

	// TrustedDeviceName is the cookie marking a browser as a remembered device.
	TrustedDeviceName = "authn_td_token"

	// Path is the path every session cookie is scoped to.
	//
	// Root, not /v1/client, because two endpoints consume the refresh cookie —
	// /v1/client/auth/refresh and /v1/oauth/token — and a cookie scoped to
	// /v1/client is never sent to the second. Widening it is what makes both
	// paths work from one cookie; the cookie is HTTPOnly and the host is the
	// engine's own, so the wider scope grants nothing new to page scripts.
	Path = "/"

	// legacyClientPath is the path the refresh cookie used to be written with.
	//
	// A browser mid-session at upgrade time holds a cookie at this path. Cookies
	// are distinguished by (name, domain, path), so the newly written root cookie
	// does not replace it, and both are then sent to /v1/client/* — where the
	// stale one may be read first and rejected. Expiring it explicitly costs one
	// header per sign-in and removes that ambiguity.
	legacyClientPath = "/v1/client"
)

// SessionPolicyResolver supplies the tenant policy governing a cookie.
//
// It is an interface so this package does not depend on the settings cache, and
// so tests can supply a policy without a database. settings.Resolver satisfies
// it.
type SessionPolicyResolver interface {
	// SessionPolicy returns the policy for one of the tenant's two environments. It
	// does not fail: callers on the login path need an answer, so implementations
	// return documented defaults rather than an error.
	SessionPolicy(ctx context.Context, tenantID, environment string) policy.SessionPolicy
}

// Writer builds and sets session cookies.
type Writer struct {
	// cfg supplies the deployment-bound attributes: Secure and Domain.
	cfg *config.Config
	// policies supplies the tenant-bound attributes. A nil resolver means every
	// tenant gets policy.DefaultSessionPolicy, which is the correct behaviour for
	// a deployment that has not wired one rather than a reason to fail.
	policies SessionPolicyResolver
}

// NewWriter returns a Writer. A nil resolver is valid and yields default policy
// for every tenant.
func NewWriter(cfg *config.Config, policies SessionPolicyResolver) *Writer {
	return &Writer{cfg: cfg, policies: policies}
}

// SetRefreshToken writes the refresh cookie for tenantID, expiring after ttl.
//
// environment selects which of the tenant's two session policies decides SameSite.
// It is passed rather than inferred because this package sits below the middleware
// that resolves it, and a cookie written under the wrong environment's policy would
// be dropped by the browser on a cross-site sign-in that the other environment
// permits.
//
// A zero or negative ttl writes a session cookie — one the browser drops when it
// closes — rather than a cookie that expires immediately, which would discard a
// perfectly good refresh token.
func (w *Writer) SetRefreshToken(c *fiber.Ctx, tenantID, environment, value string, ttl time.Duration) {
	w.clearLegacyPath(c, RefreshTokenName)
	w.set(c, RefreshTokenName, value, tenantID, environment, ttl)
}

// SetTrustedDevice writes the trusted-device cookie for tenantID.
func (w *Writer) SetTrustedDevice(c *fiber.Ctx, tenantID, environment, value string, ttl time.Duration) {
	w.set(c, TrustedDeviceName, value, tenantID, environment, ttl)
}

// ClearRefreshToken expires the refresh cookie, at both the current path and the
// legacy one, so a sign-out leaves nothing behind for either.
func (w *Writer) ClearRefreshToken(c *fiber.Ctx) {
	w.expire(c, RefreshTokenName, Path)
	w.expire(c, RefreshTokenName, legacyClientPath)
}

// SessionPolicy returns the policy that would govern a cookie for tenantID in one
// environment. Handlers computing a token lifetime from the same policy use this, so
// the token and the cookie carrying it cannot disagree about how long they last.
func (w *Writer) SessionPolicy(ctx context.Context, tenantID, environment string) policy.SessionPolicy {
	if w.policies == nil {
		return policy.DefaultSessionPolicy()
	}
	return w.policies.SessionPolicy(ctx, tenantID, environment)
}

// RefreshTokenTTL returns the refresh lifetime for tenantID, falling back to the
// deployment default when the tenant has not set one.
//
// A tenant may configure up to a year, which the test-environment ceiling then
// bounds: the tenant's setting is one value across both environments, so the
// ceiling is what keeps asking for a year in live from also handing test a
// year-long credential.
func (w *Writer) RefreshTokenTTL(ctx context.Context, tenantID, environment string) time.Duration {
	return w.cfg.ClampSessionTTL(environment,
		w.SessionPolicy(ctx, tenantID, environment).RefreshTokenTTL(w.cfg.RefreshTokenTTL))
}

// AccessTokenTTL returns the access lifetime for tenantID, falling back to the
// deployment default when the tenant has not set one, and bounded by the
// test-environment ceiling for the same reason as the refresh lifetime.
func (w *Writer) AccessTokenTTL(ctx context.Context, tenantID, environment string) time.Duration {
	return w.cfg.ClampAccessTokenTTL(environment,
		w.SessionPolicy(ctx, tenantID, environment).AccessTokenTTL(w.cfg.AccessTokenTTL))
}

// set builds one cookie and writes it.
func (w *Writer) set(c *fiber.Ctx, name, value, tenantID, environment string, ttl time.Duration) {
	secure := w.cfg.CookieSecure()
	sameSite := w.resolveSameSite(c, tenantID, environment, secure)

	cookie := &fiber.Cookie{
		Name:     name,
		Value:    value,
		Path:     Path,
		Domain:   w.cfg.CookieDomain,
		HTTPOnly: true,
		// Secure tracks the deployment's own scheme. Without it a browser sends
		// this long-lived token over cleartext HTTP, where anyone on the path can
		// capture and replay it.
		Secure:   secure,
		SameSite: sameSite,
	}
	if ttl > 0 {
		cookie.Expires = time.Now().Add(ttl)
	}

	c.Cookie(cookie)
}

// resolveSameSite decides the SameSite attribute for this tenant and request.
//
// The tenant asks for "lax" or "none"; "none" is granted only when the cookie
// will also carry Secure, because every current browser rejects the pairing of
// SameSite=None with a non-Secure cookie outright — the cookie is dropped, not
// downgraded, and the session silently fails to persist.
//
// The check lives here rather than at startup because the value is now
// runtime-changeable: a tenant may switch to "none" long after the process
// booted, and a validated-once answer would be stale. Falling back to Lax is a
// working same-site session instead of no session at all, which is the better
// failure for a deployment that has not yet moved to HTTPS.
func (w *Writer) resolveSameSite(c *fiber.Ctx, tenantID, environment string, secure bool) string {
	pol := w.SessionPolicy(c.UserContext(), tenantID, environment)
	if pol.CookieSameSite != policy.SameSiteNone {
		return "Lax"
	}
	if !secure {
		return "Lax"
	}
	return "None"
}

// expire writes a deletion for name at the given path.
//
// Deletion is a Set-Cookie with a past expiry rather than fiber's ClearCookie,
// because ClearCookie cannot target a specific path and the legacy cookie is
// only reachable at its own. Domain must match the cookie being removed, or the
// browser treats it as a different cookie and leaves the original in place.
func (w *Writer) expire(c *fiber.Ctx, name, path string) {
	c.Cookie(&fiber.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		Domain:   w.cfg.CookieDomain,
		Expires:  time.Now().Add(-time.Hour),
		MaxAge:   -1,
		HTTPOnly: true,
		Secure:   w.cfg.CookieSecure(),
	})
}

// clearLegacyPath expires a same-named cookie left at the pre-unification path,
// so the fresh root-scoped one is unambiguous.
func (w *Writer) clearLegacyPath(c *fiber.Ctx, name string) {
	w.expire(c, name, legacyClientPath)
}
