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

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
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

// createApplicationRequest is the POST /v1/tenant/applications payload.
type createApplicationRequest struct {
	// ID is the client_id the application will authenticate with.
	ID string `json:"id"`
	// Name is the human-readable application name.
	Name string `json:"name"`
	// ExactRedirectURIs is the allowlist of destinations the authorization
	// endpoint will return codes to. Entries are matched exactly.
	ExactRedirectURIs []string `json:"exact_redirect_uris"`
}

// CreateApplication handles POST /v1/tenant/applications and registers an OAuth
// client, responding 201 with the stored record.
//
// Returns 400 when id or name is missing and 500 when the write fails.
func (h *Handler) CreateApplication(c *fiber.Ctx) error {
	// This route sits behind the admin middleware, which sets the tenant on
	// success. An empty value means the request was never authenticated, so it
	// is refused rather than assigned a default tenant — creating an application
	// under the wrong tenant would hand its API keys to the wrong customer.
	tenantID, _ := c.Locals("tenant_id").(string)
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

	if err := h.service.CreateClientApplication(c.UserContext(), req.ID, tenantID, req.Name, req.ExactRedirectURIs); err != nil {
		return httperr.SendInternal(c, "oauth.create_application", err)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":             "application registered successfully",
		"id":                  req.ID,
		"name":                req.Name,
		"exact_redirect_uris": req.ExactRedirectURIs,
	})
}
