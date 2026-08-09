/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/handler.go
 * Tier: Internal Feature Package / OAuth2 & OIDC HTTP Handlers
 *
 * Description: Fiber handlers for the OAuth2 and OpenID Connect endpoints —
 *              discovery, JWKS publication and rotation, the PKCE authorization
 *              endpoint, token exchange and refresh, UserInfo, and client
 *              application registration.
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

const (
	// defaultTenantID is the tenant assumed when a request carries no tenant
	// context, which happens on single-tenant deployments where no tenant was
	// ever explicitly provisioned.
	defaultTenantID = "tnt_default"

	// refreshTokenCookieName is the canonical cookie the engine writes rotated
	// refresh tokens to.
	refreshTokenCookieName = "authn_refresh_token"

	// metadataCacheControl is sent on the discovery and JWKS documents. Both are
	// public, change only on rotation, and are fetched by every relying party.
	metadataCacheControl = "public, max-age=3600"
)

// Handler exposes the OAuth2 and OIDC endpoints over HTTP.
type Handler struct {
	// service performs the underlying OAuth2 and OIDC operations.
	service *Service
}

// NewHandler constructs a Handler bound to service.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

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

// extractAccessToken returns the caller's access token from the session
// cookies or the Authorization header, or "" when none is present.
//
// Cookies are preferred so a browser session works without the caller having to
// read the token out of storage and attach it by hand.
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

// Authorize handles GET /v1/oauth/authorize, the authorization endpoint.
//
// It requires an authenticated session, validates the client and its redirect
// URI against the registration record, and issues an authorization code bound
// to the subject taken from the verified token claims — never from a request
// parameter, which the caller controls.
//
// Responds 302 to the redirect URI carrying `code` and `state` when a redirect
// URI is supplied, otherwise 200 with the code in the body. Returns 401 when the
// session is missing or invalid, and 400 for an unsupported response type, the
// "plain" PKCE method, an unregistered client, or an unparseable redirect URI.
func (h *Handler) Authorize(c *fiber.Ctx) error {
	tokenStr := extractAccessToken(c)
	if tokenStr == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized, "unauthorized: authentication session required")
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.cfg.EncryptionKey)
	if err != nil {
		// The parse failure ("signature is invalid", "expired by 3s") is
		// diagnostic detail for an unauthenticated caller and stays out of the body.
		return httperr.Unauthorized(c, httperr.CodeInvalidToken, "unauthorized session: access token is invalid or expired")
	}

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type", "code")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method", "S256")
	scope := c.Query("scope", grantedScope)

	if strings.EqualFold(codeChallengeMethod, "plain") {
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"invalid_request: code_challenge_method 'plain' is unsupported; PKCE S256 is required")
	}

	if responseType != "code" {
		return httperr.BadRequest(c, httperr.CodeValidationFailed, "unsupported_response_type: expected response_type=code")
	}

	if err := h.service.ValidateClientApplication(c.UserContext(), clientID, redirectURI); err != nil {
		// ValidateClientApplication mixes authored rejections with a wrapped
		// storage error, so the concrete reason is collapsed into one sanitized
		// message. The caller learns which parameters are at fault, not what the
		// storage layer said.
		return httperr.BadRequest(c, httperr.CodeValidationFailed,
			"invalid_request: client_id is not registered or redirect_uri is not authorized for this client")
	}

	userID := claims.Sub
	tenantID := claims.TenantID

	codeStr, err := h.service.IssueAuthorizationCode(c.UserContext(), clientID, userID, tenantID, redirectURI, codeChallenge, codeChallengeMethod, scope)
	if err != nil {
		return httperr.SendInternal(c, "oauth.issue_authorization_code", err)
	}

	state := c.Query("state")
	if redirectURI != "" {
		// Parameters are merged through net/url rather than concatenated. A
		// registered redirect URI may already carry a query string or a fragment,
		// and appending after a fragment would bury the code where no server ever
		// sees it.
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

// TokenExchangeRequest is the POST /v1/oauth/token payload, accepted as JSON or
// as form encoding.
type TokenExchangeRequest struct {
	// GrantType selects the flow: "authorization_code" or "refresh_token".
	GrantType string `json:"grant_type" form:"grant_type"`
	// Code is the authorization code being redeemed.
	Code string `json:"code" form:"code"`
	// ClientID must match the client the code was issued to.
	ClientID string `json:"client_id" form:"client_id"`
	// RedirectURI must match the one bound at authorization time.
	RedirectURI string `json:"redirect_uri" form:"redirect_uri"`
	// CodeVerifier is the PKCE secret whose S256 hash must equal the challenge.
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
	// RefreshToken carries the token for the refresh grant when the caller does
	// not rely on the cookie.
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
}

// TokenExchange handles POST /v1/oauth/token for both supported grants.
//
// authorization_code responds 200 with the access and ID tokens, 400 when the
// code is missing or the grant fails any binding check. refresh_token responds
// 200 with a rotated pair, 400 when no token is supplied, and 401 when the token
// is invalid, expired or revoked. Any other grant type is a 400.
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
			// Which binding failed is withheld: naming it tells an attacker
			// holding a stolen code exactly which parameter still has to be
			// guessed. Storage and key-management failures are wrapped into the
			// same error value and must not reach the caller either.
			return httperr.BadRequest(c, httperr.CodeValidationFailed,
				"invalid_grant: authorization code, client_id, redirect_uri, or PKCE code_verifier is invalid or expired")
		}
		return c.Status(fiber.StatusOK).JSON(res)

	case "refresh_token":
		rawToken := req.RefreshToken
		if rawToken == "" {
			rawToken = c.Cookies(refreshTokenCookieName)
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
			// Reuse detection and revocation state stay server-side; the caller
			// only learns the token is no longer usable.
			return httperr.Unauthorized(c, httperr.CodeInvalidToken,
				"refresh token is invalid, expired, or has been revoked")
		}

		if newRawRefreshToken != "" {
			cookie := new(fiber.Cookie)
			cookie.Name = refreshTokenCookieName
			cookie.Value = newRawRefreshToken
			cookie.Expires = time.Now().Add(h.service.cfg.RefreshTokenTTL)
			cookie.HTTPOnly = true
			// Secure tracks the deployment's own scheme. Without it a browser
			// sends this long-lived token over cleartext HTTP, where anyone on
			// the path can capture and replay it.
			cookie.Secure = h.service.cfg.CookieSecure()
			cookie.SameSite = "Lax"
			cookie.Path = "/"
			c.Cookie(cookie)
		}

		res := fiber.Map{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   accessTokenExpiresInSeconds,
			"user":         userDTO,
		}

		// Native and mobile clients cannot read an HttpOnly cookie, so a caller
		// that sent the token in the body gets the rotated one back the same way.
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

// GetUserInfo handles GET /v1/oauth/userinfo and returns the subject's claims
// with a 200.
//
// Returns 401 when no access token is presented or it fails verification, and
// 404 when the verified subject has no user record.
func (h *Handler) GetUserInfo(c *fiber.Ctx) error {
	tokenStr := extractAccessToken(c)
	if tokenStr == "" {
		return httperr.Unauthorized(c, httperr.CodeUnauthorized,
			"unauthorized: access token required in Authorization header or cookie")
	}

	claims, err := jwtpkg.VerifyAccessToken(tokenStr, h.service.cfg.EncryptionKey)
	if err != nil {
		return httperr.Unauthorized(c, httperr.CodeInvalidToken, "invalid or expired access token")
	}

	info, err := h.service.GetUserInfo(c.UserContext(), claims.TenantID, claims.Sub)
	if err != nil {
		return httperr.NotFound(c, httperr.CodeNotFound, "user not found")
	}

	return c.Status(fiber.StatusOK).JSON(info)
}

// RegisterRoutes mounts the OAuth2 and OIDC endpoints on app.
//
// pkMiddleware guards the authorization and token endpoints when supplied.
// adminMiddleware, when supplied, guards key rotation and application
// registration; without it those routes are mounted unguarded, which is only
// appropriate for a test harness.
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
	tenantID, _ := c.Locals("tenant_id").(string)
	if tenantID == "" {
		tenantID = defaultTenantID
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
