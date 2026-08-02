/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/handler.go
 * Tier: Internal Feature Package / OAuth2 & OIDC HTTP Handlers
 *
 * Description: Fiber HTTP handlers for OIDC discovery, JWKS public keys,
 *              PKCE authorization code endpoint, and token exchange.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Handler handles HTTP requests for OAuth2 and OpenID Connect flows.
type Handler struct {
	service *Service
}

// NewHandler constructs a new OAuth2 Handler instance.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// GetOIDCDiscovery handles GET /.well-known/openid-configuration.
func (h *Handler) GetOIDCDiscovery(c *fiber.Ctx) error {
	scheme := c.Protocol()
	host := c.Hostname()
	issuer := fmt.Sprintf("%s://%s", scheme, host)
	discovery := h.service.GetDiscoveryMetadata(issuer)
	return c.Status(fiber.StatusOK).JSON(discovery)
}

// GetJWKS handles GET /v1/oauth/jwks.
func (h *Handler) GetJWKS(c *fiber.Ctx) error {
	rsaKey, err := jwtpkg.GetOrGenerateRSAPrivateKey(h.service.cfg.JWTSigningKeyPath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed generating public JWKS"})
	}
	jwks := jwtpkg.ExportRSAPublicJWKS(&rsaKey.PublicKey, h.service.cfg.AuthnKeyID)
	return c.Status(fiber.StatusOK).JSON(jwks)
}

// extractAccessToken attempts to find an active access token from cookies or Authorization Bearer header.
func extractAccessToken(c *fiber.Ctx) string {
	if tok := c.Cookies("authn_access_token"); tok != "" {
		return tok
	}
	if tok := c.Cookies("access_token"); tok != "" {
		return tok
	}
	authHeader := c.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

// Authorize handles GET /v1/oauth/authorize.
// Requires a valid authenticated session (session cookie or Bearer access token).
// Validates client_id and redirect_uri against database registration before issuing code.
// Binds authorization code strictly to the verified caller's subject ID from session claims.
func (h *Handler) Authorize(c *fiber.Ctx) error {
	tokenStr := extractAccessToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized: authentication session required",
		})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.cfg.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": fmt.Sprintf("unauthorized session: %v", err),
		})
	}

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type", "code")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method", "S256")
	scope := c.Query("scope", "openid profile email")

	if responseType != "code" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported_response_type: expected response_type=code"})
	}

	// 1. Validate registered client Application and authorized redirect URI
	if err := h.service.ValidateClientApplication(c.Context(), clientID, redirectURI); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// 2. User ID comes strictly from verified session claims (claims.Sub)
	userID := claims.Sub
	tenantID := claims.TenantID

	codeStr, err := h.service.IssueAuthorizationCode(c.Context(), clientID, userID, tenantID, redirectURI, codeChallenge, codeChallengeMethod, scope)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if redirectURI != "" {
		redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, codeStr)
		return c.Redirect(redirectURL, fiber.StatusFound)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"code":      codeStr,
		"tenant_id": tenantID,
		"scope":     scope,
	})
}

// TokenExchangeRequest defines payload for POST /v1/oauth/token.
type TokenExchangeRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	ClientID     string `json:"client_id" form:"client_id"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
}

// TokenExchange handles POST /v1/oauth/token.
func (h *Handler) TokenExchange(c *fiber.Ctx) error {
	var req TokenExchangeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.GrantType != "authorization_code" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported_grant_type: expected grant_type=authorization_code"})
	}

	if req.Code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_request: code is required"})
	}

	res, err := h.service.ExchangeCodeForTokens(c.Context(), req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(res)
}

// RegisterRoutes registers OAuth2 and OIDC endpoints.
func (h *Handler) RegisterRoutes(app *fiber.App) {
	app.Get("/.well-known/openid-configuration", h.GetOIDCDiscovery)

	group := app.Group("/v1/oauth")
	group.Get("/jwks", h.GetJWKS)
	group.Get("/authorize", h.Authorize)
	group.Post("/token", h.TokenExchange)
}
