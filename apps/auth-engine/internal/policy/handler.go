/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/handler.go
 * Tier: Internal Feature Package / Policy Handler
 *
 * Admin HTTP endpoints for reading and configuring a tenant's password,
 * security, recovery and session policies, and for publishing a rehearsed
 * configuration from one environment to the other.
 *
 * Every route is admin-only: these settings decide how strong a password must
 * be, whether verification is enforced, how long a session lasts, and how an
 * account can be recovered, so they carry the same guard as key management.
 *
 * Which environment a route acts on is taken from the credential, never from the
 * request. A secret key names one environment, so sk_test_ configures test and
 * sk_live_ configures live, and there is no way to reach live settings while
 * holding a test key. Each response echoes the environment it acted on, because
 * "I changed the policy and nothing happened" is otherwise indistinguishable from
 * having configured the other environment by mistake.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
)

// SettingsInvalidator drops cached policy for one of a tenant's environments.
//
// It is an interface because the settings cache depends on this package, so the
// dependency cannot run the other way. settings.Resolver satisfies it.
type SettingsInvalidator interface {
	// InvalidateTenantPolicy evicts the cached session policy for one tenant and
	// environment. It does not report failure: an eviction that does not land costs
	// one TTL of staleness, which is not a reason to fail a write that already
	// succeeded.
	InvalidateTenantPolicy(ctx context.Context, tenantID, environment string)
}

// Handler serves the tenant policy endpoints.
type Handler struct {
	// repo reads and writes policies on the tenant's per-environment settings row.
	repo *Repository
	// invalidator evicts cached policy after a write. Nil is valid and means
	// readers observe a change once the cache TTL elapses.
	invalidator SettingsInvalidator
}

// NewHandler returns a policy handler backed by repo.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// WithSettingsInvalidator attaches the cache whose entries policy writes evict,
// and returns the handler for chaining.
func (h *Handler) WithSettingsInvalidator(inv SettingsInvalidator) *Handler {
	h.invalidator = inv
	return h
}

// scopeOf returns the tenant and environment the request acts within, or answers
// 401 and reports false. Callers must return nil when it reports false.
//
// Both come from the credential the admin guard verified, never from the request,
// so a caller holding a valid key for one tenant cannot address another by naming
// it, and a caller holding a test key cannot configure live.
func scopeOf(c *fiber.Ctx) (tenantID, environment string, ok bool) {
	tenantID, ok = middleware.RequireTenantID(c)
	if !ok {
		return "", "", false
	}
	return tenantID, middleware.GetEnvironment(c), true
}

// invalidate evicts the cached policy for one environment when a cache is attached.
func (h *Handler) invalidate(c *fiber.Ctx, tenantID, environment string) {
	if h.invalidator != nil {
		h.invalidator.InvalidateTenantPolicy(c.UserContext(), tenantID, environment)
	}
}

// envelope wraps a policy with the environment it belongs to.
//
// The policy is inlined rather than nested so an existing client reading
// `min_length` at the top level keeps working, while a client that wants to
// confirm which environment answered can read `environment`.
func envelope(environment string, policy any) map[string]any {
	out := map[string]any{}
	if data, err := json.Marshal(policy); err == nil {
		_ = json.Unmarshal(data, &out)
	}
	out["environment"] = environment
	return out
}

// GetPolicy handles GET /v1/tenant/password-policy, answering 200 with the
// password policy of the credential's environment or 500 when it cannot be read.
func (h *Handler) GetPolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}
	p, err := h.repo.GetPasswordPolicy(c.UserContext(), tenantID, environment)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_password_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(envelope(environment, p))
}

// UpdatePolicy handles PUT /v1/tenant/password-policy, answering 200 with the
// stored policy, 400 for an unparseable body, and 500 when the write fails.
// Out-of-range lengths are clamped by the repository rather than rejected.
func (h *Handler) UpdatePolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}

	var req PasswordPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdatePasswordPolicy(c.UserContext(), tenantID, environment, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_password_policy", err)
	}

	h.invalidate(c, tenantID, environment)
	return c.Status(fiber.StatusOK).JSON(envelope(environment, updated))
}

// GetSecurityPolicy handles GET /v1/tenant/security-policy, answering 200 with
// the security policy of the credential's environment or 500 when it cannot be
// read.
func (h *Handler) GetSecurityPolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}
	sp, err := h.repo.GetSecurityPolicy(c.UserContext(), tenantID, environment)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_security_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(envelope(environment, sp))
}

// UpdateSecurityPolicy handles PUT /v1/tenant/security-policy, answering 200
// with the stored policy, 400 for an unparseable body, and 500 when the write
// fails. Unrecognised enum values fall back to their defaults.
func (h *Handler) UpdateSecurityPolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}

	var req SecurityPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateSecurityPolicy(c.UserContext(), tenantID, environment, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_security_policy", err)
	}

	h.invalidate(c, tenantID, environment)
	return c.Status(fiber.StatusOK).JSON(envelope(environment, updated))
}

// GetRecoveryPolicy handles GET /v1/tenant/recovery-policy, answering 200 with
// the recovery policy of the credential's environment or 500 when it cannot be
// read.
func (h *Handler) GetRecoveryPolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}
	rp, err := h.repo.GetRecoveryPolicy(c.UserContext(), tenantID, environment)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_recovery_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(envelope(environment, rp))
}

// UpdateRecoveryPolicy handles PUT /v1/tenant/recovery-policy, answering 200
// with the stored policy, 400 for an unparseable body, and 400 when the policy
// is rejected.
//
// The repository reports both rule violations and write failures through one
// error, and the write failures carry ORM and SQL text, so the detail stops at
// the log and the caller receives a fixed message pointing at the documented
// limits.
func (h *Handler) UpdateRecoveryPolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}

	var req RecoveryPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	updated, err := h.repo.UpdateRecoveryPolicy(c.UserContext(), tenantID, environment, req)
	if err != nil {
		log.Printf("[error] %s %s policy.update_recovery_policy: %v", c.Method(), c.Path(), err)
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"recovery policy rejected: review freeze window, claim token TTL, lockout schedule, and method toggles against the documented limits")
	}

	h.invalidate(c, tenantID, environment)
	return c.Status(fiber.StatusOK).JSON(envelope(environment, updated))
}

// GetSessionPolicy handles GET /v1/tenant/session-policy, answering 200 with the
// session policy of the credential's environment or 500 when it cannot be read.
func (h *Handler) GetSessionPolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}
	sp, err := h.repo.GetSessionPolicy(c.UserContext(), tenantID, environment)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_session_policy", err)
	}
	return c.Status(fiber.StatusOK).JSON(envelope(environment, sp))
}

// UpdateSessionPolicy handles PUT /v1/tenant/session-policy, answering 200 with
// the stored policy, 400 for an unparseable body, 422 for an access-token
// lifetime off the menu, and 500 when the write fails.
//
// The access lifetime is rejected rather than corrected because a caller asking
// for 45 minutes and being given 30 has no way to notice: it is a fixed menu, not
// a range, so an unlisted value is a mistake to report rather than an
// approximation to fill in. The refresh lifetime and the SameSite value are still
// normalized by the repository, which is the older contract on those fields.
//
// The response carries what was stored, which is what the caller should read back
// rather than assuming the request was applied verbatim.
func (h *Handler) UpdateSessionPolicy(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}

	var req SessionPolicy
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if !ValidAccessTokenTTLMinutes(req.AccessTokenTTLMinutes) {
		return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed,
			"access_token_ttl_minutes must be 15, 30 or 60, or omitted to inherit the deployment default")
	}

	updated, err := h.repo.UpdateSessionPolicy(c.UserContext(), tenantID, environment, req)
	if err != nil {
		return httperr.SendInternal(c, "policy.update_session_policy", err)
	}

	h.invalidate(c, tenantID, environment)
	return c.Status(fiber.StatusOK).JSON(envelope(environment, updated))
}

// GetSettings handles GET /v1/tenant/settings, answering 200 with every policy
// column of the credential's environment as stored.
//
// Client secrets are redacted. The typed per-policy endpoints are the ones to
// configure against; this is the whole configuration in one read, for a console
// showing what an environment currently holds.
func (h *Handler) GetSettings(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}

	snapshot, err := h.repo.Snapshot(c.UserContext(), tenantID, environment)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_settings", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"environment": environment,
		"settings":    snapshot.Redacted(),
	})
}

// GetSettingsDiff handles GET /v1/tenant/settings/diff, answering 200 with both
// environments' stored settings and the list of columns that differ.
//
// This is what an administrator reads before publishing: it answers "what will
// change in live if I promote test", which is the question that makes the test
// environment worth configuring separately. Readable with either key because it
// only reads, and client secrets are redacted on both sides.
func (h *Handler) GetSettingsDiff(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}

	test, err := h.repo.Snapshot(c.UserContext(), tenantID, EnvironmentTest)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_settings_diff", err)
	}
	live, err := h.repo.Snapshot(c.UserContext(), tenantID, EnvironmentLive)
	if err != nil {
		return httperr.SendInternal(c, "policy.get_settings_diff", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"environment": environment,
		"test":        test.Redacted(),
		"live":        live.Redacted(),
		"differs":     DifferingFields(test, live),
	})
}

// publishRequest names the environments a publish moves settings between.
type publishRequest struct {
	// From is the environment whose settings are copied. Defaults to test.
	From string `json:"from"`
	// To is the environment overwritten. Defaults to live, and must match the
	// credential's environment.
	To string `json:"to"`
}

// PublishSettings handles POST /v1/tenant/settings/publish, answering 200 with
// the settings that were published, 400 for an unparseable body or an
// environment pair that names one environment twice, 403 when the credential does
// not govern the destination, 404 for an unknown tenant, and 500 when the write
// fails.
//
// The destination must be the credential's own environment. That is the guard
// that matters here: without it a test key could overwrite a live configuration,
// which is the one thing the environment split exists to prevent. Reading the
// source across the boundary is safe by comparison — it is the same tenant's data,
// and a publish that could not read test could not publish anything.
func (h *Handler) PublishSettings(c *fiber.Ctx) error {
	tenantID, environment, ok := scopeOf(c)
	if !ok {
		return nil
	}

	req := publishRequest{From: EnvironmentTest, To: EnvironmentLive}
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return httperr.InvalidBody(c)
		}
	}
	if req.From == "" {
		req.From = EnvironmentTest
	}
	if req.To == "" {
		req.To = EnvironmentLive
	}

	if !ValidEnvironment(req.From) || !ValidEnvironment(req.To) {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"from and to must each be \"test\" or \"live\"")
	}
	if req.From == req.To {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"from and to must name different environments")
	}
	if req.To != environment {
		return httperr.Forbidden(c, httperr.CodeForbidden,
			"publishing into "+req.To+" requires a "+req.To+" secret key")
	}

	result, err := h.repo.Publish(c.UserContext(), tenantID, req.From, req.To)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			return httperr.NotFound(c, httperr.CodeNotFound, "tenant not found")
		}
		return httperr.SendInternal(c, "policy.publish_settings", err)
	}

	// Logged rather than returned: the promotion is already durable, and answering
	// with a failure would invite an operator to publish a second time.
	if err := h.repo.RecordPublish(c.UserContext(), tenantID, PublishAudit{
		From:      req.From,
		To:        req.To,
		Changed:   result.Changed,
		ActorID:   actorOf(c),
		APIKeyID:  localString(c, "api_key_id"),
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
		Origin:    c.Get("Origin"),
	}); err != nil {
		log.Printf("[error] %s %s policy.record_publish tenant=%s: %v", c.Method(), c.Path(), tenantID, err)
	}

	h.invalidate(c, tenantID, req.To)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "settings published",
		"from":     req.From,
		"to":       req.To,
		"changed":  result.Changed,
		"settings": result.Settings.Redacted(),
	})
}

// actorOf names who is publishing, preferring a console session over the API key
// the request authenticated with.
//
// Publishing is attributed to a person where one can be identified, because "who
// changed what governs live" is the question the audit row exists to answer. A
// key-only caller leaves the key ID as the closest available answer.
func actorOf(c *fiber.Ctx) string {
	for _, key := range []string{"console_user_id", "user_id", "userID", "api_key_id"} {
		if val := localString(c, key); val != "" {
			return val
		}
	}
	return ""
}

// localString reads a string request local, or "" when it is absent or of another
// type.
func localString(c *fiber.Ctx, key string) string {
	val, _ := c.Locals(key).(string)
	return val
}

// RegisterRoutes mounts the policy endpoints behind skMiddleware, the secret-key
// admin guard. All of them are admin operations and share one guard, so no policy
// route can be added on a weaker one by accident.
func (h *Handler) RegisterRoutes(app *fiber.App, skMiddleware fiber.Handler) {
	mw := skMiddleware

	passwordGroup := app.Group("/v1/tenant/password-policy")
	passwordGroup.Get("", mw, h.GetPolicy)
	passwordGroup.Put("", mw, h.UpdatePolicy)

	securityGroup := app.Group("/v1/tenant/security-policy")
	securityGroup.Get("", mw, h.GetSecurityPolicy)
	securityGroup.Put("", mw, h.UpdateSecurityPolicy)

	recoveryGroup := app.Group("/v1/tenant/recovery-policy")
	recoveryGroup.Get("", mw, h.GetRecoveryPolicy)
	recoveryGroup.Put("", mw, h.UpdateRecoveryPolicy)

	sessionGroup := app.Group("/v1/tenant/session-policy")
	sessionGroup.Get("", mw, h.GetSessionPolicy)
	sessionGroup.Put("", mw, h.UpdateSessionPolicy)

	settingsGroup := app.Group("/v1/tenant/settings")
	settingsGroup.Get("", mw, h.GetSettings)
	settingsGroup.Get("/diff", mw, h.GetSettingsDiff)
	settingsGroup.Post("/publish", mw, h.PublishSettings)
}
