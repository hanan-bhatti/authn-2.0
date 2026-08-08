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
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
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
	jwks := h.service.GetPublicJWKS()
	c.Set("Cache-Control", "public, max-age=3600")
	return c.Status(fiber.StatusOK).JSON(jwks)
}

// RotateJWKS handles POST /v1/admin/jwks/rotate (admin-scoped manual key rotation).
func (h *Handler) RotateJWKS(c *fiber.Ctx) error {
	newKey, err := h.service.RotateJWKSKey()
	if err != nil {
		return httperr.SendInternal(c, "oauth.rotate_jwks", err)
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "JWKS key successfully rotated",
		"new_active_key_id": newKey.ID,
		"jwks": h.service.GetPublicJWKS(),
	})
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
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: authentication session required")
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.cfg.AuthnEncryptionKey)
	if err != nil {
		// The parse failure itself ("token signature is invalid", "token is
		// expired by 3s") is diagnostic detail for an unauthenticated caller and
		// no longer reaches the body.
		return httperr.Unauthorized(c, httperr.CodeInvalidToken, "unauthorized session: access token is invalid or expired")
	}

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type", "code")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method", "S256")
	scope := c.Query("scope", "openid profile email")

	if strings.EqualFold(codeChallengeMethod, "plain") {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"invalid_request: code_challenge_method 'plain' is unsupported; PKCE S256 is required")
	}

	if responseType != "code" {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "unsupported_response_type: expected response_type=code")
	}

	// 1. Validate registered client Application and authorized redirect URI
	if err := h.service.ValidateClientApplication(c.UserContext(), clientID, redirectURI); err != nil {
		// ValidateClientApplication mixes authored rejections with a wrapped
		// database error ("failed querying client application: %w"), so the
		// concrete reason is collapsed into one sanitized message rather than
		// echoed. The caller learns which parameters are at fault, not what the
		// storage layer said.
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"invalid_request: client_id is not registered or redirect_uri is not authorized for this client")
	}

	// 2. User ID comes strictly from verified session claims (claims.Sub)
	userID := claims.Sub
	tenantID := claims.TenantID

	codeStr, err := h.service.IssueAuthorizationCode(c.UserContext(), clientID, userID, tenantID, redirectURI, codeChallenge, codeChallengeMethod, scope)
	if err != nil {
		return httperr.SendInternal(c, "oauth.issue_authorization_code", err)
	}

	state := c.Query("state")
	if redirectURI != "" {
		// Built through net/url rather than string concatenation: the previous
		// "?"/"&" sniff mis-placed the parameters whenever the registered
		// redirect_uri carried a fragment, appending them inside the fragment
		// where no server ever sees them.
		u, err := url.Parse(redirectURI)
		if err != nil {
			return httperr.BadRequest(c, httperr.CodeValidationFailed, "invalid_request: redirect_uri is not a valid URL")
		}
		q := u.Query()
		q.Set("code", codeStr)
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		return c.Redirect(u.String(), fiber.StatusFound)
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
		return httperr.InvalidBody(c)
	}

	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			return httperr.BadRequest(c, httperr.CodeMissingParameter, "invalid_request: code is required")
		}

		res, err := h.service.ExchangeCodeForTokens(c.UserContext(), req.Code, req.ClientID, req.RedirectURI, req.CodeVerifier)
		if err != nil {
			// ExchangeCodeForTokens wraps storage and key-management failures
			// ("failed retrieving user for authorization code: %w"), so the
			// reason is collapsed to a single sanitized grant rejection. Status
			// stays 400 exactly as before.
			return httperr.BadRequest(c, httperr.CodeValidationFailed,
				"invalid_grant: authorization code, client_id, redirect_uri, or PKCE code_verifier is invalid or expired")
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
			return httperr.BadRequest(c, httperr.CodeMissingParameter,
				"invalid_request: refresh token is required in request body or authn_refresh_token cookie")
		}

		userAgent := c.Get("User-Agent")
		ipAddress := c.IP()

		userDTO, accessToken, newRawRefreshToken, err := h.service.RotateRefreshTokenSession(c.UserContext(), rawToken, userAgent, ipAddress)
		if err != nil {
			// Reuse-detection and revocation detail stays server-side; the
			// caller only learns the token is no longer usable.
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"refresh token is invalid, expired, or has been revoked")
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
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"unsupported_grant_type: expected grant_type=authorization_code or grant_type=refresh_token")
	}
}

// GetUserInfo handles GET /v1/oauth/userinfo (OIDC Standard UserInfo Endpoint).
// Requires a valid Bearer access token in Authorization header or authn_access_token cookie.
func (h *Handler) GetUserInfo(c *fiber.Ctx) error {
	tokenStr := extractAccessToken(c)
	if tokenStr == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"unauthorized: access token required in Authorization header or cookie")
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.cfg.AuthnEncryptionKey)
	if err != nil {
		return httperr.Unauthorized(c, httperr.CodeInvalidToken, "invalid or expired access token")
	}

	info, err := h.service.GetUserInfo(c.UserContext(), claims.TenantID, claims.Sub)
	if err != nil {
		// GetUserInfo already collapses both the query failure and the missing
		// row into "user not found", so 404 is preserved.
		return httperr.NotFound(c, httperr.CodeNotFound, "user not found")
	}

	return c.Status(fiber.StatusOK).JSON(info)
}

// RegisterRoutes registers OAuth2 and OIDC endpoints.
func (h *Handler) RegisterRoutes(app *fiber.App, pkMiddleware fiber.Handler, adminMiddleware ...fiber.Handler) {
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

	if len(adminMiddleware) > 0 && adminMiddleware[0] != nil {
		adminGroup := app.Group("/v1/admin", adminMiddleware[0])
		adminGroup.Post("/jwks/rotate", h.RotateJWKS)

		tenantAdminGroup := app.Group("/v1/tenant", adminMiddleware[0])
		tenantAdminGroup.Post("/applications", h.CreateApplication)
	} else {
		app.Post("/v1/admin/jwks/rotate", h.RotateJWKS)
		app.Post("/v1/tenant/applications", h.CreateApplication)
	}
}

type createApplicationRequest struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	ExactRedirectURIs []string `json:"exact_redirect_uris"`
}

func (h *Handler) CreateApplication(c *fiber.Ctx) error {
	tenantID, _ := c.Locals("tenant_id").(string)
	if tenantID == "" {
		tenantID = "tnt_default"
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
