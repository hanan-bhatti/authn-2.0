/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/oauth_discovery_handlers.go
 * Tier: Delivery Layer / Fiber HTTP Handlers
 *
 * Description: Fiber HTTP handlers for OIDC discovery, JWKS metadata publication & rotation, and client application registration.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
)

// GetOIDCDiscovery handles GET /.well-known/openid-configuration and returns
// the discovery document with a 200.
//
// The request's own scheme and host are offered as the issuer fallback so a
// deployment that has not set an explicit issuer still publishes a coherent
// document.
func (h *Handler) GetOIDCDiscovery(c *fiber.Ctx) error {
	scheme := c.Protocol()
	host := c.Hostname()
	requestIssuer := fmt.Sprintf("%s://%s", scheme, host)
	discovery := h.service.GetDiscoveryMetadata(requestIssuer)

	c.Set("Cache-Control", metadataCacheControl)
	return c.Status(fiber.StatusOK).JSON(discovery)
}

// GetJWKS handles GET /v1/oauth/jwks and returns the public key set with a 200.
func (h *Handler) GetJWKS(c *fiber.Ctx) error {
	jwks := h.service.GetPublicJWKS()
	c.Set("Cache-Control", metadataCacheControl)
	return c.Status(fiber.StatusOK).JSON(jwks)
}

// RotateJWKS handles POST /v1/admin/jwks/rotate, promoting a new signing key
// and returning the updated key set with a 200.
//
// Returns 500 if no key manager is available.
func (h *Handler) RotateJWKS(c *fiber.Ctx) error {
	newKey, err := h.service.RotateJWKSKey()
	if err != nil {
		return httperr.SendInternal(c, "oauth.rotate_jwks", err)
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":           "JWKS key successfully rotated",
		"new_active_key_id": newKey.ID,
		"jwks":              h.service.GetPublicJWKS(),
	})
}

// applicationResponse is the shape every application-management route returns.
//
// It carries only fields the owning tenant may see and edit. These routes sit
// behind the admin middleware, so the caller is the tenant that owns the record
// and echoing its own configured origins back is expected — unlike the
// publishable-key path, which must never reveal a tenant's origins to a public
// key holder.
type applicationResponse struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Environment        string   `json:"environment"`
	AllowedCorsOrigins []string `json:"allowed_cors_origins"`
	ExactRedirectURIs  []string `json:"exact_redirect_uris"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

// toApplicationResponse projects an ent.Application onto the wire DTO. Nil slices
// become empty arrays so a client always receives a JSON list rather than null.
func toApplicationResponse(app *ent.Application) applicationResponse {
	cors := app.AllowedCorsOrigins
	if cors == nil {
		cors = []string{}
	}
	uris := app.ExactRedirectUris
	if uris == nil {
		uris = []string{}
	}
	return applicationResponse{
		ID:                 app.ID,
		Name:               app.Name,
		Environment:        string(app.Environment),
		AllowedCorsOrigins: cors,
		ExactRedirectURIs:  uris,
		CreatedAt:          app.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:          app.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// normalizeCorsOrigins validates and normalizes a caller-supplied origin list.
//
// Each entry must be a bare origin (scheme + host + optional port); anything with
// a path, query, fragment, credentials, or the "*" wildcard is rejected, because
// it can never match the Origin header a browser sends and would be a silently
// dead allowlist entry. Normalization uses the same NormalizeOrigin the
// request-path matcher uses, so a stored origin and an incoming one compare
// identically. Duplicates are collapsed. It returns the offending entry when one
// fails so the caller can name it in the 400.
func normalizeCorsOrigins(raw []string) ([]string, string, bool) {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		normalized, ok := middleware.ValidateOrigin(entry)
		if !ok {
			return nil, entry, false
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, "", true
}

// tenantFromLocals returns the tenant the admin middleware resolved, or "" when
// the request was never authenticated. Creating or mutating an application under
// an unresolved tenant would attach it to the wrong customer, so callers refuse
// an empty value rather than assign a default.
func tenantFromLocals(c *fiber.Ctx) string {
	v, _ := c.Locals("tenant_id").(string)
	return v
}

// createApplicationRequest is the POST /v1/tenant/applications payload.
type createApplicationRequest struct {
	// ID is the client_id the application will authenticate with.
	ID string `json:"id"`
	// Name is the human-readable application name.
	Name string `json:"name"`
	// ExactRedirectURIs is the allowlist of destinations the authorization
	// endpoint will return codes to. Entries are matched exactly.
	ExactRedirectURIs []string `json:"exact_redirect_uris"`
	// AllowedCorsOrigins is the browser-origin allowlist the application's
	// publishable keys may be called from. Empty means "not configured" — origin
	// checks fall back to the deployment-wide CORS policy.
	AllowedCorsOrigins []string `json:"allowed_cors_origins"`
}

// CreateApplication handles POST /v1/tenant/applications and registers an OAuth
// client, responding 201 with the stored record.
//
// Returns 400 when id or name is missing or an origin is malformed, 409 when the
// client_id is already taken, and 500 when the write fails.
func (h *Handler) CreateApplication(c *fiber.Ctx) error {
	tenantID := tenantFromLocals(c)
	if tenantID == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request")
	}

	var req createApplicationRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if req.ID == "" || req.Name == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "id and name are required")
	}

	corsOrigins, bad, ok := normalizeCorsOrigins(req.AllowedCorsOrigins)
	if !ok {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			fmt.Sprintf("allowed_cors_origins contains an invalid origin: %q — each must be a scheme and host with no path", bad))
	}

	// The environment is fixed by the credential the admin authenticated with, not
	// chosen in the body: a test-scoped key must not be able to mint a live-scoped
	// application. An empty value lets the schema default (test) apply.
	env, _ := c.Locals("environment").(string)

	app, err := h.service.CreateClientApplication(c.UserContext(), req.ID, tenantID, req.Name, env, req.ExactRedirectURIs, corsOrigins)
	if err != nil {
		if ent.IsConstraintError(err) {
			return httperr.Conflict(c, httperr.CodeAlreadyExists,
				"an application with this id already exists")
		}
		return httperr.SendInternal(c, "oauth.create_application", err)
	}

	// A brand-new application has nothing cached, but invalidating is cheap and
	// keeps every write path uniform: create, update and delete all drop the entry
	// so the resolver never serves a stale row after a mutation.
	h.invalidateApplication(c, app.ID)

	return c.Status(fiber.StatusCreated).JSON(toApplicationResponse(app))
}

// ListApplications handles GET /v1/tenant/applications and returns the caller's
// tenant's applications, oldest first, with a 200.
func (h *Handler) ListApplications(c *fiber.Ctx) error {
	if tenantFromLocals(c) == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request")
	}

	apps, err := h.service.ListClientApplications(c.UserContext())
	if err != nil {
		return httperr.SendInternal(c, "oauth.list_applications", err)
	}

	out := make([]applicationResponse, 0, len(apps))
	for _, app := range apps {
		out = append(out, toApplicationResponse(app))
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"applications": out})
}

// GetApplication handles GET /v1/tenant/applications/:id and returns one
// application within the caller's tenant with a 200.
//
// A cross-tenant or unknown id is answered 404 identically, so the endpoint never
// reveals that an id exists under a different tenant.
func (h *Handler) GetApplication(c *fiber.Ctx) error {
	if tenantFromLocals(c) == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request")
	}

	app, err := h.service.GetClientApplication(c.UserContext(), c.Params("id"))
	if err != nil {
		return httperr.SendInternal(c, "oauth.get_application", err)
	}
	if app == nil {
		return httperr.NotFound(c, httperr.CodeNotFound, "application not found")
	}
	return c.Status(fiber.StatusOK).JSON(toApplicationResponse(app))
}

// updateApplicationRequest is the PATCH /v1/tenant/applications/:id payload. Each
// field is a pointer so an omitted field is left unchanged, while a present-but-
// empty array explicitly clears the list.
type updateApplicationRequest struct {
	Name               *string   `json:"name"`
	ExactRedirectURIs  *[]string `json:"exact_redirect_uris"`
	AllowedCorsOrigins *[]string `json:"allowed_cors_origins"`
}

// UpdateApplication handles PATCH /v1/tenant/applications/:id, applying a partial
// update within the caller's tenant and returning the updated record with a 200.
//
// Returns 400 when an origin is malformed and 404 when no such application exists
// in this tenant — the same answer a cross-tenant id receives.
func (h *Handler) UpdateApplication(c *fiber.Ctx) error {
	if tenantFromLocals(c) == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request")
	}

	var req updateApplicationRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	// Normalize origins before touching storage so a bad entry is a 400, not a
	// half-applied write. A present list is normalized even when empty: an empty
	// slice is the caller clearing the allowlist, distinct from an omitted (nil)
	// field that leaves it untouched.
	if req.AllowedCorsOrigins != nil {
		normalized, bad, ok := normalizeCorsOrigins(*req.AllowedCorsOrigins)
		if !ok {
			return httperr.BadRequest(c, httperr.CodeValidationFailed,
				fmt.Sprintf("allowed_cors_origins contains an invalid origin: %q — each must be a scheme and host with no path", bad))
		}
		req.AllowedCorsOrigins = &normalized
	}

	app, err := h.service.UpdateClientApplication(c.UserContext(), c.Params("id"), req.Name, req.ExactRedirectURIs, req.AllowedCorsOrigins)
	if err != nil {
		return httperr.SendInternal(c, "oauth.update_application", err)
	}
	if app == nil {
		return httperr.NotFound(c, httperr.CodeNotFound, "application not found")
	}

	// The edit may have changed the CORS allowlist or redirect URIs the resolver
	// caches, so drop the entry to force a fresh read on the next request.
	h.invalidateApplication(c, app.ID)

	return c.Status(fiber.StatusOK).JSON(toApplicationResponse(app))
}

// DeleteApplication handles DELETE /v1/tenant/applications/:id, removing an
// application within the caller's tenant and answering 204.
//
// A cross-tenant or unknown id is answered 404, matching GetApplication so a
// delete probe cannot distinguish "not yours" from "does not exist".
func (h *Handler) DeleteApplication(c *fiber.Ctx) error {
	if tenantFromLocals(c) == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"tenant could not be resolved for this request")
	}

	id := c.Params("id")
	deleted, err := h.service.DeleteClientApplication(c.UserContext(), id)
	if err != nil {
		return httperr.SendInternal(c, "oauth.delete_application", err)
	}
	if !deleted {
		return httperr.NotFound(c, httperr.CodeNotFound, "application not found")
	}

	h.invalidateApplication(c, id)
	return c.SendStatus(fiber.StatusNoContent)
}

// invalidateApplication drops an application's cached settings so a mutation is
// visible on the next request instead of after the cache TTL. It is a no-op when
// no settings resolver is wired — a deployment without the cache simply reads the
// row directly every time.
func (h *Handler) invalidateApplication(c *fiber.Ctx, id string) {
	if h.settings != nil {
		h.settings.InvalidateApplication(c.UserContext(), id)
	}
}
