/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/handler.go
 * Tier: Internal Feature Package / Admin Key HTTP Handlers
 *
 * HTTP routes for issuing, listing and revoking an application's API keys.
 *
 * Every route sits behind admin authentication, so managing keys requires a
 * credential that already carries administrative authority — either an sk_
 * secret key or a tenant_admin console token. A publishable key can never mint
 * a secret one.
 *
 * The two credential kinds differ in reach, which is why the handlers resolve
 * the target application rather than reading it from one place: an sk_ key is
 * bound to a single application, while a console token is tenant-wide and must
 * name the application, subject to a tenant check.
 *
 * Environments are isolated in both directions: a caller authenticated with a
 * test-mode key cannot create or see live-mode keys, and the reverse holds too.
 * Without that, a test credential — the kind that ends up in a shared fixture
 * or a CI log — would be a route to live access.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package apikey

import (
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// CreateKeyRequest is the body of a key issuance request.
type CreateKeyRequest struct {
	// ApplicationID names the application the key is issued for. It is required
	// of a tenant-wide caller such as the console, and optional for a backend
	// authenticated with an sk_ key, whose application is already known — such a
	// caller may only name its own.
	ApplicationID string `json:"application_id,omitempty" example:"app_00000000000000000000000000000001"`
	// Name is an operator-facing label for the key.
	Name string `json:"name" example:"Production Stripe Webhook Key"`
	// Type is the requested scope: "publishable" or "secret".
	Type string `json:"type" example:"publishable"`
	// Environment is "test" or "live". It must match the caller's own
	// environment, and defaults to it when omitted.
	Environment string `json:"environment" example:"test"`
	// ExpiresInDays sets an optional lifetime. Omitting it issues a key that
	// stays valid until revoked.
	ExpiresInDays *int `json:"expires_in_days,omitempty"`
}

// KeyDTO is the public view of a key. It carries no hash and no key material,
// so it is safe to return in a listing.
type KeyDTO struct {
	// ID is the key's identifier, used to revoke it.
	ID string `json:"id" example:"key_1a2b3c"`
	// ApplicationID is the owning application.
	ApplicationID string `json:"application_id" example:"app_00000000000000000000000000000001"`
	// Name is the operator-facing label.
	Name string `json:"name" example:"Production Key"`
	// Type is the key's scope.
	Type string `json:"type" example:"publishable"`
	// KeyPrefix is the key's leading marker, enough to recognise a key without
	// revealing it.
	KeyPrefix string `json:"key_prefix" example:"pk_test_"`
	// Environment is "test" or "live".
	Environment string `json:"environment" example:"test"`
	// CreatedAt is the issue time in RFC 3339.
	CreatedAt string `json:"created_at" example:"2026-08-01T12:00:00Z"`
	// ExpiresAt is the expiry in RFC 3339, omitted when the key does not expire.
	ExpiresAt *string `json:"expires_at,omitempty"`
	// RevokedAt is the revocation time in RFC 3339, omitted while the key is
	// active.
	RevokedAt *string `json:"revoked_at,omitempty"`
}

// CreateKeyResponse is returned when a key is issued.
type CreateKeyResponse struct {
	// Key is the new key's metadata.
	Key KeyDTO `json:"key"`
	// RawKey is the usable key. This response is the only place it ever
	// appears: it is not stored and cannot be retrieved again.
	RawKey string `json:"raw_key" example:"pk_test_12345678901234567890123456789012"`
}

// Handler serves the key management routes.
type Handler struct {
	// service performs issuance, listing and revocation.
	service *Service
}

// NewHandler constructs a handler over a key service.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes mounts the key management routes under /v1/admin/keys.
//
// adminMiddleware authenticates the caller and populates the tenant,
// environment, and — for an application-bound credential — the application the
// handlers read. It is applied when non-nil; passing nil leaves the routes
// unauthenticated and suits only a test that supplies those values itself.
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware fiber.Handler) {
	group := app.Group("/v1/admin/keys")
	if adminMiddleware != nil {
		group.Use(adminMiddleware)
	}
	group.Post("/", h.CreateKey)
	group.Get("/", h.ListKeys)
	group.Post("/:id/revoke", h.RevokeKey)
}

// resolveApplicationID determines which application a key request acts on.
//
// Two kinds of caller reach these routes. A backend holding an sk_ key is bound
// to the application that issued it, and the middleware puts that application in
// the request locals; such a caller may not name a different one. The console
// holds a tenant_admin JWT instead, which is tenant-wide and application-less,
// so it must name the application — and that value, coming from the request, is
// checked against the caller's tenant before it is used.
//
// Returns the resolved application id, or a ready-to-return error response.
func (h *Handler) resolveApplicationID(c *fiber.Ctx, requested string) (string, error) {
	tenantID, okTenant := c.Locals("tenant_id").(string)
	if !okTenant || tenantID == "" {
		return "", httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: tenant context missing")
	}

	localAppID, _ := c.Locals("application_id").(string)
	requested = strings.TrimSpace(requested)

	// An application-bound credential ignores the request's value, but refuses
	// rather than silently overriding when the two disagree: a caller asking for
	// an application it cannot act on has made a mistake worth reporting.
	if localAppID != "" {
		if requested != "" && requested != localAppID {
			return "", httperr.BadRequest(c, httperr.CodeValidationFailed,
				"application_id does not match the authenticating key's application")
		}
		return localAppID, nil
	}

	if requested == "" {
		return "", httperr.BadRequest(c, httperr.CodeMissingParameter,
			"application_id is required: a tenant-wide admin credential must name the application to act on")
	}

	ok, err := h.service.ApplicationInTenant(c.UserContext(), requested, tenantID)
	if err != nil {
		return "", httperr.SendInternal(c, "apikey.resolve_application", err)
	}
	if !ok {
		// A foreign application and an absent one answer identically, so the
		// response cannot be used to discover which applications exist.
		return "", httperr.NotFound(c, httperr.CodeNotFound, "application not found")
	}
	return requested, nil
}

// CreateKey issues a key for an application in the caller's tenant and returns
// it once.
//
// Responds 401 when the middleware left no tenant context, 400 for an
// unparseable body, an unrecognised type, a missing or mismatched
// application_id, or an environment differing from the caller's, 404 when the
// named application is not in the caller's tenant, 500 when issuance fails, and
// 201 with the key on success.
func (h *Handler) CreateKey(c *fiber.Ctx) error {
	callerEnv, okEnv := c.Locals("environment").(string)
	if !okEnv || callerEnv == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: environment context missing")
	}

	var req CreateKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	appID, err := h.resolveApplicationID(c, req.ApplicationID)
	if err != nil {
		return err
	}

	keyType := KeyType(strings.ToLower(strings.TrimSpace(req.Type)))
	if keyType != TypePublishable && keyType != TypeSecret {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "invalid key type: expected 'publishable' or 'secret'")
	}

	reqEnv := strings.ToLower(strings.TrimSpace(req.Environment))
	if reqEnv == "" {
		reqEnv = callerEnv
	}

	// The requested environment must equal the caller's. Comparing rather than
	// simply overriding means a request that names the wrong environment is
	// reported as a mistake instead of quietly producing a key for a different
	// one than the operator asked for.
	if reqEnv != callerEnv {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"environment mismatch: test-mode admin key cannot manage live-mode keys and vice versa")
	}

	var expiresAt *time.Time
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		exp := time.Now().AddDate(0, 0, *req.ExpiresInDays)
		expiresAt = &exp
	}

	gen, err := h.service.CreateKey(c.UserContext(), "", appID, req.Name, keyType, reqEnv, expiresAt)
	if err != nil {
		return httperr.SendInternal(c, "apikey.create_key", err)
	}
	dto := KeyDTO{
		ID:            gen.ID,
		ApplicationID: appID,
		Name:          req.Name,
		Type:          string(gen.Type),
		KeyPrefix:     gen.Prefix,
		Environment:   reqEnv,
		CreatedAt:     time.Now().Format(time.RFC3339),
	}
	if expiresAt != nil {
		expStr := expiresAt.Format(time.RFC3339)
		dto.ExpiresAt = &expStr
	}

	return c.Status(fiber.StatusCreated).JSON(CreateKeyResponse{
		Key:    dto,
		RawKey: gen.RawKey,
	})
}

// ListKeys returns the metadata of every key belonging to an application in the
// caller's tenant, revoked and expired ones included.
//
// A backend authenticated with an sk_ key lists that key's own application; the
// console names one via ?application_id=, checked against its tenant.
//
// Responds 401 when the middleware left no tenant context, 400 when a
// tenant-wide caller names no application, 404 when the named application is
// not in the caller's tenant, 500 if the query fails, and 200 with the list —
// never containing key material — on success.
func (h *Handler) ListKeys(c *fiber.Ctx) error {
	appID, err := h.resolveApplicationID(c, c.Query("application_id"))
	if err != nil {
		return err
	}

	keys, err := h.service.ListKeys(c.UserContext(), appID)
	if err != nil {
		return httperr.SendInternal(c, "apikey.list_keys", err)
	}

	dtos := make([]KeyDTO, 0, len(keys))
	for _, k := range keys {
		dtos = append(dtos, toKeyDTO(k))
	}

	return c.Status(fiber.StatusOK).JSON(dtos)
}

// RevokeKey marks a key unusable.
//
// Revocation is confined to the caller's own tenant, so a key id belonging to
// another tenant is refused exactly as an unknown one is.
//
// Responds 401 when the middleware left no tenant context, 400 when the id is
// missing or names no revocable key in that tenant, and 200 on success. The
// failure is reported as a 400 with fixed wording, because the underlying error
// distinguishes "no such key" from "already revoked" from "another tenant's
// key", and relaying that would let a caller probe which identifiers exist.
func (h *Handler) RevokeKey(c *fiber.Ctx) error {
	tenantID, okTenant := c.Locals("tenant_id").(string)
	if !okTenant || tenantID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: tenant context missing")
	}

	keyID := c.Params("id")
	if keyID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "key id is required")
	}

	if err := h.service.RevokeKey(c.UserContext(), keyID, tenantID); err != nil {
		// The repository wraps the ent failure together with the key id, so the
		// detail is logged rather than returned.
		log.Printf("[error] %s %s apikey.revoke_key: %v", c.Method(), c.Path(), err)
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"api key could not be revoked: unknown or already-revoked key id")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "revoked", "id": keyID})
}

// toKeyDTO projects a key record onto its public view, formatting timestamps as
// RFC 3339 and omitting the optional ones when unset.
func toKeyDTO(k *ent.ApiKey) KeyDTO {
	dto := KeyDTO{
		ID:            k.ID,
		ApplicationID: k.ApplicationID,
		Name:          k.Name,
		Type:          string(k.Type),
		KeyPrefix:     k.KeyPrefix,
		Environment:   string(k.Environment),
		CreatedAt:     k.CreatedAt.Format(time.RFC3339),
	}
	if k.ExpiresAt != nil {
		expStr := k.ExpiresAt.Format(time.RFC3339)
		dto.ExpiresAt = &expStr
	}
	if k.RevokedAt != nil {
		revStr := k.RevokedAt.Format(time.RFC3339)
		dto.RevokedAt = &revStr
	}
	return dto
}
