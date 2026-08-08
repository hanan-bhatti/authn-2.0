/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/handler.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Fiber HTTP handlers for social OAuth2 authorize/callback flows
 *              and admin provider configuration endpoints.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"errors"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware, adminMiddleware fiber.Handler) {
	// Client routes
	clientGroup := app.Group("/v1/client/auth/social")
	if pkMiddleware != nil {
		clientGroup.Use(pkMiddleware)
	}
	clientGroup.Get("/:provider/authorize", h.Authorize)
	clientGroup.Get("/:provider/callback", h.Callback)

	// Admin routes
	adminGroup := app.Group("/v1/tenant/social-providers")
	if adminMiddleware != nil {
		adminGroup.Use(adminMiddleware)
	}
	adminGroup.Get("", h.ListProviders)
	adminGroup.Get("/:provider", h.GetProvider)
	adminGroup.Put("/:provider", h.ConfigureProvider)
	adminGroup.Delete("/:provider", h.DeleteProvider)
}

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
			// `email_exists_social_account` is a wire contract with the SDK — the
			// code stays byte-identical through the envelope migration.
			return httperr.Send(c, fiber.StatusConflict, "email_exists_social_account", err.Error())
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

// buildPostCallbackRedirect attaches the issued access token to the application's
// post-callback destination.
//
// Audit H5(a) — the token moves from the query string to the URL *fragment*. A
// query parameter is written to the browser's history, this server's access log,
// every intermediate proxy log, and the Referer header of any cross-origin
// subresource the landing page fetches; a fragment is never transmitted to any
// server, so the token stays inside the browser that earned it.
//
// Audit H5(b) — the previous implementation concatenated "?access_token=" onto
// the base unconditionally and escaped nothing. A destination that already
// carried a query string ("https://app.example.com/cb?tenant=acme") produced a
// second "?" and the token silently became part of the `tenant` value, so login
// appeared to hang. Parsing with net/url and encoding through url.Values keeps
// an existing query intact and escapes both components.
func buildPostCallbackRedirect(base, accessToken string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	// Any fragment already on the destination is dropped — this slot is ours.
	u.Fragment = ""
	u.RawFragment = ""

	frag := url.Values{}
	frag.Set("access_token", accessToken)
	frag.Set("token_type", "Bearer")

	// Appended literally rather than assigned to u.Fragment: url.URL.String()
	// re-escapes the Fragment field, which would percent-encode the already
	// encoded output of Values.Encode() a second time and hand the client a
	// mangled token.
	return u.String() + "#" + frag.Encode(), nil
}

func (h *Handler) ListProviders(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)

	results, err := h.svc.GetSetupGuide(c.UserContext(), tenantID, "")
	if err != nil {
		return httperr.SendInternal(c, "social.list_providers", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"providers": results})
}

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

type configureProviderRequest struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

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
			// clientErr.Error() is fully authored ("[google] invalid client_id:
			// must end with .apps.googleusercontent.com") — no wrapped internals.
			// The offending field is named in the prose now that the envelope
			// carries only `error` and `code`.
			return httperr.UnprocessableEntity(c, httperr.CodeValidationFailed, clientErr.Error())
		}
		return httperr.SendInternal(c, "social.configure_provider", err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "provider configured successfully",
		"provider": provider,
	})
}

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
