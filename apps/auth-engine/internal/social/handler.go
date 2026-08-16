/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/handler.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Fiber handlers for the social sign-in round trip — the authorize
 *              redirect and the provider callback — and the tenant-facing
 *              endpoints for inspecting and configuring provider credentials.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"errors"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/accountstatus"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

// emailExistsSocialCode is returned when a social profile's address already
// belongs to another account. It is a wire contract with the SDK, which
// branches on this exact string.
const emailExistsSocialCode = "email_exists_social_account"

// Handler exposes the social sign-in and provider configuration endpoints.
type Handler struct {
	// svc performs the underlying social authentication work.
	svc *Service
}

// NewHandler constructs a Handler bound to svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes mounts the social endpoints on app.
//
// pkMiddleware guards the client sign-in routes and establishes the tenant,
// application and environment those handlers read. adminMiddleware guards the
// provider configuration routes.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware, adminMiddleware fiber.Handler) {
	clientGroup := app.Group("/v1/client/auth/social")
	if pkMiddleware != nil {
		clientGroup.Use(pkMiddleware)
	}
	clientGroup.Get("/:provider/authorize", h.Authorize)
	clientGroup.Get("/:provider/callback", h.Callback)

	adminGroup := app.Group("/v1/tenant/social-providers")
	if adminMiddleware != nil {
		adminGroup.Use(adminMiddleware)
	}
	adminGroup.Get("", h.ListProviders)
	adminGroup.Get("/:provider", h.GetProvider)
	adminGroup.Put("/:provider", h.ConfigureProvider)
	adminGroup.Delete("/:provider", h.DeleteProvider)
}

// Authorize handles GET /v1/client/auth/social/:provider/authorize and responds
// 302 to the provider's consent screen.
//
// Returns 400 when redirect_uri is missing, when the provider is not configured
// or enabled, or when post_callback_redirect is not an authorized destination
// for the calling application, and 500 otherwise.
func (h *Handler) Authorize(c *fiber.Ctx) error {
	provider := c.Params("provider")
	tenantID, _ := c.Locals("tenant_id").(string)
	applicationID, _ := c.Locals("application_id").(string)
	environment, _ := c.Locals("environment").(string)

	redirectURI := c.Query("redirect_uri")
	if redirectURI == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "redirect_uri query parameter is required")
	}
	postCallbackRedirect := c.Query("post_callback_redirect")

	authURL, err := h.svc.InitiateAuthorize(c.UserContext(), tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect)
	if err != nil {
		if errors.Is(err, ErrProviderNotConfigured) || errors.Is(err, ErrProviderNotEnabled) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, err.Error())
		}
		if errors.Is(err, ErrRedirectNotAllowed) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, err.Error())
		}
		return httperr.SendInternal(c, "social.authorize", err)
	}

	return c.Redirect(authURL, fiber.StatusFound)
}

// Callback handles GET /v1/client/auth/social/:provider/callback, the
// destination the provider returns the user to.
//
// On success it responds 302 to the application's authorized destination with
// the access token in the URL fragment, or 200 with the token in the body when
// no destination applies.
//
// Returns 400 when code or state is missing, when the state is unknown or
// expired, or when the provider returned no email; 409 when the address belongs
// to another account; and 500 otherwise.
func (h *Handler) Callback(c *fiber.Ctx) error {
	provider := c.Params("provider")
	code := c.Query("code")
	stateToken := c.Query("state")

	tenantID, _ := c.Locals("tenant_id").(string)

	if code == "" || stateToken == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "code and state query parameters are required")
	}

	accessToken, postCallbackRedirect, err := h.svc.HandleCallback(c.UserContext(), tenantID, provider, stateToken, code)
	if err != nil {
		if errors.Is(err, ErrEmailConflict) {
			return httperr.Send(c, fiber.StatusConflict, emailExistsSocialCode, err.Error())
		}
		if errors.Is(err, ErrStateNotFound) {
			return httperr.BadRequest(c, httperr.CodeInvalidToken, err.Error())
		}
		if errors.Is(err, ErrStateExpired) {
			return httperr.BadRequest(c, httperr.CodeSessionExpired, err.Error())
		}
		if errors.Is(err, ErrEmailRequired) || errors.Is(err, ErrProviderNotConfigured) {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, err.Error())
		}
		if accountstatus.Refused(err) {
			return httperr.Send(c, fiber.StatusForbidden, httperr.CodeAccountDisabled, accountstatus.PublicMessage(err))
		}
		return httperr.SendInternal(c, "social.callback", err)
	}

	if postCallbackRedirect != "" {
		redirectURL, err := buildPostCallbackRedirect(postCallbackRedirect, accessToken)
		if err != nil {
			return httperr.SendInternal(c, "social.callback.build_redirect", err)
		}
		return c.Redirect(redirectURL, fiber.StatusFound)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
	})
}

// buildPostCallbackRedirect returns base with the access token attached in the
// URL fragment.
//
// The token must stay in the fragment and must not be moved to the query
// string. A fragment is never transmitted to any server, so the token stays
// inside the browser that earned it. A query parameter, by contrast, is written
// to the browser's history, this server's access log, every proxy log along the
// way, and the Referer header of any cross-origin subresource the landing page
// loads.
//
// The URL is assembled through net/url so a destination that already carries a
// query string keeps it intact and both components are escaped; concatenating
// would produce a second "?" and fold the token into the preceding parameter's
// value.
//
// The fragment is appended literally rather than assigned to url.URL.Fragment,
// because URL.String re-escapes that field and would percent-encode the encoded
// values a second time, handing the client a mangled token. Any fragment
// already on the destination is dropped, since this slot carries the token.
//
// Returns an error if base is not a parseable URL.
func buildPostCallbackRedirect(base, accessToken string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	u.Fragment = ""
	u.RawFragment = ""

	frag := url.Values{}
	frag.Set("access_token", accessToken)
	frag.Set("token_type", "Bearer")

	return u.String() + "#" + frag.Encode(), nil
}

// ListProviders handles GET /v1/tenant/social-providers and responds 200 with
// every supported provider and its configuration state.
//
// Returns 500 if the tenant's configuration cannot be read.
func (h *Handler) ListProviders(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)

	results, err := h.svc.GetSetupGuide(c.UserContext(), tenantID, "")
	if err != nil {
		return httperr.SendInternal(c, "social.list_providers", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"providers": results})
}

// GetProvider handles GET /v1/tenant/social-providers/:provider and responds
// 200 with that provider's configuration state and setup guidance.
//
// Returns 404 for an unrecognized provider and 500 if the read fails.
func (h *Handler) GetProvider(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)
	provider := c.Params("provider")

	results, err := h.svc.GetSetupGuide(c.UserContext(), tenantID, provider)
	if err != nil {
		return httperr.SendInternal(c, "social.get_provider", err)
	}

	if len(results) == 0 {
		return httperr.NotFound(c, httperr.CodeNotFound, "provider not found")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"provider": results[0]})
}

// configureProviderRequest is the PUT /v1/tenant/social-providers/:provider
// payload.
type configureProviderRequest struct {
	// Enabled switches the provider on or off for the tenant.
	Enabled bool `json:"enabled"`
	// ClientID is the provider-issued public client identifier.
	ClientID string `json:"client_id"`
	// ClientSecret is the provider-issued secret. Empty keeps the stored one,
	// which an administrator cannot read back to re-submit.
	ClientSecret string `json:"client_secret"`
}

// ConfigureProvider handles PUT /v1/tenant/social-providers/:provider and
// responds 200 once the credentials are stored.
//
// Returns 400 when client_id is missing, 422 when a credential fails the
// provider's format rules, and 500 otherwise.
func (h *Handler) ConfigureProvider(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)
	provider := c.Params("provider")

	var req configureProviderRequest
	if err := c.BodyParser(&req); err != nil {
		return httperr.InvalidBody(c)
	}

	if req.ClientID == "" {
		return httperr.BadRequest(c, httperr.CodeMissingParameter, "client_id is required")
	}

	err := h.svc.ConfigureProvider(c.UserContext(), tenantID, provider, req.Enabled, req.ClientID, req.ClientSecret)
	if err != nil {
		var clientErr *ErrInvalidClientCredentials
		if errors.As(err, &clientErr) {
			// This message is fully authored by the validator and names the
			// offending field, so it carries no wrapped internal detail.
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed, clientErr.Error())
		}
		return httperr.SendInternal(c, "social.configure_provider", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "provider configured successfully",
		"provider": provider,
	})
}

// DeleteProvider handles DELETE /v1/tenant/social-providers/:provider and
// responds 200 once the configuration is removed.
//
// Returns 500 if the write fails.
func (h *Handler) DeleteProvider(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)
	provider := c.Params("provider")

	if err := h.svc.RemoveProvider(c.UserContext(), tenantID, provider); err != nil {
		return httperr.SendInternal(c, "social.delete_provider", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "provider removed",
		"provider": provider,
	})
}
