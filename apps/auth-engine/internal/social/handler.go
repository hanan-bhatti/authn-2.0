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

	"github.com/gofiber/fiber/v2"
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "redirect_uri query parameter is required"})
	}
	postCallbackRedirect := c.Query("post_callback_redirect")

	authURL, err := h.svc.InitiateAuthorize(c.UserContext(), tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect)
	if err != nil {
		if errors.Is(err, ErrProviderNotConfigured) || errors.Is(err, ErrProviderNotEnabled) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Redirect(authURL, fiber.StatusFound)
}

func (h *Handler) Callback(c *fiber.Ctx) error {
	provider := c.Params("provider")
	code := c.Query("code")
	stateToken := c.Query("state")

	tenantID, _ := c.Locals("tenant_id").(string)

	if code == "" || stateToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "code and state query parameters are required"})
	}

	accessToken, postCallbackRedirect, err := h.svc.HandleCallback(c.UserContext(), tenantID, provider, stateToken, code)
	if err != nil {
		if errors.Is(err, ErrEmailConflict) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": err.Error(),
				"code":  "email_exists_social_account",
			})
		}
		if errors.Is(err, ErrStateNotFound) || errors.Is(err, ErrStateExpired) || errors.Is(err, ErrEmailRequired) || errors.Is(err, ErrProviderNotConfigured) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if postCallbackRedirect != "" {
		redirectURL := postCallbackRedirect + "?access_token=" + accessToken
		return c.Redirect(redirectURL, fiber.StatusFound)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
	})
}

func (h *Handler) ListProviders(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)

	results, err := h.svc.GetSetupGuide(c.UserContext(), tenantID, "")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"providers": results})
}

func (h *Handler) GetProvider(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)
	provider := c.Params("provider")

	results, err := h.svc.GetSetupGuide(c.UserContext(), tenantID, provider)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if len(results) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "provider not found"})
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.ClientID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "client_id is required"})
	}

	err := h.svc.ConfigureProvider(c.UserContext(), tenantID, provider, req.Enabled, req.ClientID, req.ClientSecret)
	if err != nil {
		var clientErr *ErrInvalidClientCredentials
		if errors.As(err, &clientErr) {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{
				"error": err.Error(),
				"field": clientErr.Field,
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":  "provider removed",
		"provider": provider,
	})
}
