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
	"time"

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
	requestIssuer := fmt.Sprintf("%s://%s", scheme, host)
	discovery := h.service.GetDiscoveryMetadata(requestIssuer)

	c.Set("Cache-Control", "public, max-age=3600")
	return c.Status(fiber.StatusOK).JSON(discovery)
}

// GetJWKS handles GET /v1/oauth/jwks.
func (h *Handler) GetJWKS(c *fiber.Ctx) error {
	rsaKey, err := jwtpkg.GetOrGenerateRSAPrivateKey(h.service.cfg.JWTSigningKeyPath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed generating public JWKS"})
	}
	jwks := jwtpkg.ExportRSAPublicJWKS(&rsaKey.PublicKey, h.service.cfg.AuthnKeyID)
	c.Set("Cache-Control", "public, max-age=3600")
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
	if err := h.service.ValidateClientApplication(c.UserContext(), clientID, redirectURI); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// 2. User ID comes strictly from verified session claims (claims.Sub)
	userID := claims.Sub
	tenantID := claims.TenantID

	codeStr, err := h.service.IssueAuthorizationCode(c.UserContext(), clientID, userID, tenantID, redirectURI, codeChallenge, codeChallengeMethod, scope)
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
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
}

// TokenExchange handles POST /v1/oauth/token.
func (h *Handler) TokenExchange(c *fiber.Ctx) error {
	var req TokenExchangeRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_request: code is required"})
		}

		res, err := h.service.ExchangeCodeForTokens(c.UserContext(), req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusOK).JSON(res)

	case "refresh_token":
		// Read refresh token from JSON body OR HttpOnly cookie
		rawToken := req.RefreshToken
		if rawToken == "" {
			rawToken = c.Cookies("authn_refresh_token")
		}
		if rawToken == "" {
			rawToken = c.Cookies("refresh_token")
		}
		if rawToken == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid_request: refresh token is required in request body or authn_refresh_token cookie",
			})
		}

		userAgent := c.Get("User-Agent")
		ipAddress := c.IP()

		userDTO, accessToken, newRawRefreshToken, err := h.service.RotateRefreshTokenSession(c.UserContext(), rawToken, userAgent, ipAddress)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}

		// Set updated HttpOnly cookie if new token was issued
		if newRawRefreshToken != "" {
			cookie := new(fiber.Cookie)
			cookie.Name = "authn_refresh_token"
			cookie.Value = newRawRefreshToken
			cookie.Expires = time.Now().Add(30 * 24 * time.Hour)
			cookie.HTTPOnly = true
			cookie.SameSite = "Lax"
			cookie.Path = "/"
			c.Cookie(cookie)
		}

		res := fiber.Map{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   900,
			"user":         userDTO,
		}

		// For native/mobile client requests (or when refresh token was sent in body), include refresh_token in JSON body too
		if req.RefreshToken != "" || newRawRefreshToken != "" {
			if newRawRefreshToken != "" {
				res["refresh_token"] = newRawRefreshToken
			} else {
				res["refresh_token"] = rawToken
			}
		}

		return c.Status(fiber.StatusOK).JSON(res)

	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "unsupported_grant_type: expected grant_type=authorization_code or grant_type=refresh_token",
		})
	}
}

// GetUserInfo handles GET /v1/oauth/userinfo (OIDC Standard UserInfo Endpoint).
// Requires a valid Bearer access token in Authorization header or authn_access_token cookie.
func (h *Handler) GetUserInfo(c *fiber.Ctx) error {
	tokenStr := extractAccessToken(c)
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized: access token required in Authorization header or cookie",
		})
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.cfg.AuthnEncryptionKey)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": fmt.Sprintf("invalid or expired access token: %v", err),
		})
	}

	info, err := h.service.GetUserInfo(c.UserContext(), claims.TenantID, claims.Sub)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(info)
}

// RegisterRoutes registers OAuth2 and OIDC endpoints.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware fiber.Handler) {
	app.Get("/.well-known/openid-configuration", h.GetOIDCDiscovery)

	group := app.Group("/v1/oauth")
	group.Get("/jwks", h.GetJWKS)
	group.Get("/userinfo", h.GetUserInfo)
	if pkMiddleware != nil {
		group.Get("/authorize", pkMiddleware, h.Authorize)
		group.Post("/token", pkMiddleware, h.TokenExchange)
	} else {
		group.Get("/authorize", h.Authorize)
		group.Post("/token", h.TokenExchange)
	}
}
