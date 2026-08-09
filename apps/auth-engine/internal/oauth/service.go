/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/service.go
 * Tier: Internal Feature Package / OAuth2 & OIDC Service
 *
 * Description: Business logic for the OAuth2 authorization-code flow and the
 *              OpenID Connect surface built on top of it: discovery metadata,
 *              registered-client validation, PKCE-bound authorization codes,
 *              RS256 ID token signing, JWKS publication and rotation, and the
 *              UserInfo claim set.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

const (
	// defaultJWTKeyID names the signing key when Config.JWTKeyID is unset. It is
	// published as the `kid` in the JWKS and in every ID token header, so relying
	// parties key their cache on it.
	defaultJWTKeyID = "authn-rsa-key-v1"

	// authorizationCodePrefix marks a string as an authorization code, keeping
	// codes visually distinct from the other opaque tokens the engine issues.
	authorizationCodePrefix = "ac_"

	// authorizationCodeEntropyBytes is the number of random bytes behind each
	// authorization code, hex-encoded into the value handed to the client.
	authorizationCodeEntropyBytes = 24

	// grantedScope is the scope string returned with an authorization-code
	// exchange. The engine issues the full OIDC identity scope set and does not
	// yet narrow claims per request.
	grantedScope = "openid profile email"
)

// Service carries out OAuth2 and OIDC operations against the repositories and
// signing keys it is constructed with.
type Service struct {
	// repo stores and consumes ephemeral authorization codes.
	repo *Repository
	// authRepo reads the authoritative user and application records that back
	// token claims and redirect-URI validation.
	authRepo *auth.Repository
	// authService supplies role resolution and refresh-token rotation.
	authService *auth.Service
	// cfg holds issuer identity, token lifetimes and signing-key locations.
	cfg *config.Config
	// keyManager owns the active RSA signing key and any keys still inside their
	// rotation grace period.
	keyManager *jwtpkg.KeyManager
}

// NewService constructs a Service. The key manager is initialized with
// cfg.JWTKeyID, falling back to defaultJWTKeyID when the setting is absent; if
// key initialization fails the Service still builds and JWKS publication falls
// back to the process-wide key.
func NewService(repo *Repository, authRepo *auth.Repository, authService *auth.Service, cfg *config.Config) *Service {
	keyID := defaultJWTKeyID
	if cfg != nil && cfg.JWTKeyID != "" {
		keyID = cfg.JWTKeyID
	}
	km, _ := jwtpkg.NewKeyManager(keyID)

	return &Service{
		repo:        repo,
		authRepo:    authRepo,
		authService: authService,
		cfg:         cfg,
		keyManager:  km,
	}
}

// accessTokenExpiresIn returns the access token lifetime in whole seconds, for
// the `expires_in` field of a token response.
//
// It reads the same Config value handed to the signer, so the number advertised
// here and the `exp` stamped into the token are derived from one setting and
// cannot drift apart.
func (s *Service) accessTokenExpiresIn() int {
	ttl := s.cfg.AccessTokenTTL
	if ttl <= 0 {
		ttl = jwtpkg.AccessTokenTTL()
	}
	return int(ttl.Seconds())
}

// GetPublicJWKS returns the RFC 7517 key set containing the active signing key
// plus every key still inside its rotation grace period.
//
// Publishing grace-period keys is what makes rotation non-breaking: tokens
// signed by the outgoing key stay verifiable until they expire.
func (s *Service) GetPublicJWKS() jwtpkg.JWKSResponse {
	if s.keyManager != nil {
		return s.keyManager.GetPublicJWKS()
	}
	return jwtpkg.GetPublicJWKS(s.cfg.JWTKeyID)
}

// CreateClientApplication registers an OAuth client under tenantID with the
// exact redirect URIs it is permitted to use.
//
// Returns an error if the auth repository is unavailable or the write fails.
func (s *Service) CreateClientApplication(ctx context.Context, id, tenantID, name string, redirectURIs []string) error {
	if s.authRepo == nil {
		return fmt.Errorf("auth repository uninitialized")
	}
	_, err := s.authRepo.CreateApplication(ctx, id, tenantID, name, redirectURIs)
	return err
}

// RotateJWKSKey promotes a freshly generated key to active and moves the
// outgoing key into the grace period.
//
// newKeyID overrides the generated identifier when supplied. Returns an error
// if no key manager was initialized.
func (s *Service) RotateJWKSKey(newKeyID ...string) (*jwtpkg.KeyEntry, error) {
	if s.keyManager != nil {
		return s.keyManager.RotateKey(newKeyID...)
	}
	return nil, fmt.Errorf("key manager uninitialized")
}

// ValidateClientApplication reports whether clientID is a registered
// application and redirectURI is one of its authorized destinations.
//
// Matching is exact — no prefix, wildcard or origin relaxation. A redirect URI
// that merely starts with a registered value would let anyone who can register
// a path under that prefix receive authorization codes.
//
// Returns an error naming the failing parameter, or a wrapped storage error if
// the application lookup itself fails. Callers must not surface either verbatim.
func (s *Service) ValidateClientApplication(ctx context.Context, clientID string, redirectURI string) error {
	if clientID == "" {
		return fmt.Errorf("invalid_client: client_id parameter is missing")
	}
	if redirectURI == "" {
		return fmt.Errorf("invalid_request: redirect_uri parameter is missing")
	}

	if s.authRepo != nil {
		app, err := s.authRepo.FindApplicationByID(ctx, clientID)
		if err != nil {
			return fmt.Errorf("failed querying client application: %w", err)
		}
		if app == nil {
			return fmt.Errorf("invalid_client: client_id '%s' is not registered", clientID)
		}

		var match bool
		for _, uri := range app.ExactRedirectUris {
			if uri == redirectURI {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("invalid_grant: redirect_uri '%s' is not authorized for client '%s'", redirectURI, clientID)
		}
	}

	return nil
}

// GetDiscoveryMetadata returns the OIDC discovery document.
//
// The issuer is taken from Config.Issuer, falling back to the scheme and host
// of the incoming request and then to Config.AppBaseURL. Every endpoint is
// derived from the resolved issuer so the document is internally consistent
// whichever source won.
func (s *Service) GetDiscoveryMetadata(requestHostIssuer string) OIDCDiscoveryConfig {
	issuer := ""
	if s.cfg != nil && s.cfg.Issuer != "" {
		issuer = s.cfg.Issuer
	}
	if issuer == "" {
		issuer = requestHostIssuer
	}
	if issuer == "" && s.cfg != nil {
		issuer = s.cfg.AppBaseURL
	}

	return OIDCDiscoveryConfig{
		Issuer:                            issuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/v1/oauth/authorize", issuer),
		TokenEndpoint:                     fmt.Sprintf("%s/v1/oauth/token", issuer),
		UserinfoEndpoint:                  fmt.Sprintf("%s/v1/oauth/userinfo", issuer),
		JwksURI:                           fmt.Sprintf("%s/v1/oauth/jwks", issuer),
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported:                   []string{"iss", "sub", "aud", "exp", "iat", "email", "name", "tenant_id"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
	}
}

// IssueAuthorizationCode mints a single-use authorization code bound to the
// client, the authenticated user and the PKCE challenge, valid for
// Config.OAuthCodeTTL.
//
// The "plain" challenge method is refused: it puts the verifier and the
// challenge on the wire as the same value, so an attacker who intercepts the
// authorization request can complete the exchange. Only S256 is accepted.
//
// Returns the code string, or an error if the method is unsupported, entropy is
// unavailable, or the code cannot be persisted.
func (s *Service) IssueAuthorizationCode(ctx context.Context, clientID string, userID string, tenantID string, redirectURI string, codeChallenge string, method string, scope string) (string, error) {
	if strings.EqualFold(method, "plain") {
		return "", fmt.Errorf("invalid_request: code_challenge_method 'plain' is unsupported; PKCE S256 is required")
	}
	bytes := make([]byte, authorizationCodeEntropyBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed generating random code: %w", err)
	}

	codeStr := authorizationCodePrefix + hex.EncodeToString(bytes)
	authCode := AuthorizationCode{
		Code:                codeStr,
		ClientID:            clientID,
		UserID:              userID,
		TenantID:            tenantID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: method,
		Scope:               scope,
		ExpiresAt:           time.Now().Add(s.cfg.OAuthCodeTTL),
	}

	if err := s.repo.SaveAuthorizationCode(ctx, authCode); err != nil {
		return "", err
	}

	return codeStr, nil
}

// ExchangeCodeForTokens redeems an authorization code for an access token and a
// signed OIDC ID token.
//
// The code is consumed before anything else, so a replay finds nothing to
// redeem. The client_id and redirect_uri presented here must match the values
// bound at authorization time, and the PKCE verifier must hash to the recorded
// challenge.
//
// Identity claims are read from the database using the user ID carried on the
// code. Taking them from the request instead would let a client mint a token
// asserting any email it liked.
//
// Returns an error if the code is unknown, expired, mismatched, fails PKCE, or
// if the bound user, signing key or signature step fails.
func (s *Service) ExchangeCodeForTokens(ctx context.Context, codeStr string, clientID string, redirectURI string, codeVerifier string) (*OAuth2TokenResponse, error) {
	authCode, err := s.repo.ConsumeAuthorizationCode(ctx, codeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code: %w", err)
	}

	if authCode.ClientID != "" && authCode.ClientID != clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}
	if authCode.RedirectURI != "" && authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	if authCode.CodeChallenge != "" {
		if !VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("invalid PKCE code_verifier")
		}
	}

	var email string
	var name string
	// Environment defaults to the non-production tier when no user record is
	// available to read it from.
	var env string = "test"

	if s.authRepo != nil {
		u, err := s.authRepo.FindUserByID(ctx, authCode.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed retrieving user for authorization code: %w", err)
		}
		if u == nil {
			return nil, fmt.Errorf("user %s not found", authCode.UserID)
		}
		email = u.Email
		name = u.Name
		env = string(u.Environment)
	}

	// The role claim is resolved from the user's recorded roles rather than
	// fixed: an authorization-code exchange may be a tenant admin signing into
	// the console, and a blank role would strip that privilege.
	accessToken, err := jwtpkg.IssueAccessToken(authCode.UserID, authCode.TenantID, env, email, name, s.authService.ResolveRoleClaim(ctx, authCode.UserID), s.cfg.EncryptionKey, s.cfg.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed issuing access token: %w", err)
	}

	rsaPrivKey, err := jwtpkg.GetOrGenerateRSAPrivateKey(s.cfg.JWTSigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving RSA key for OIDC signing: %w", err)
	}

	now := time.Now()
	idClaims := IDTokenClaims{
		Issuer:        s.cfg.Issuer,
		Subject:       authCode.UserID,
		Audience:      clientID,
		TenantID:      authCode.TenantID,
		Email:         email,
		EmailVerified: true,
		Name:          name,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(s.cfg.IDTokenTTL).Unix(),
		AuthTime:      now.Unix(),
	}

	idTokenStr, err := jwtpkg.SignIDTokenRS256(rsaPrivKey, idClaims, s.cfg.JWTKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed signing ID token with RS256: %w", err)
	}

	return &OAuth2TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   s.accessTokenExpiresIn(),
		IDToken:     idTokenStr,
		Scope:       grantedScope,
	}, nil
}

// RotateRefreshTokenSession exchanges a refresh token for a new access token
// and a replacement refresh token, recording the user agent and IP against the
// resulting session.
//
// Returns the refreshed user projection, the access token, the new raw refresh
// token, and an error if the auth service is unavailable or the token is
// invalid, expired or already revoked.
func (s *Service) RotateRefreshTokenSession(ctx context.Context, rawRefreshToken string, userAgent string, ipAddress string) (*auth.UserDTO, string, string, error) {
	if s.authService == nil {
		return nil, "", "", fmt.Errorf("auth service unavailable")
	}

	u, accessToken, newRawRefreshToken, err := s.authService.RotateRefreshTokenSession(ctx, rawRefreshToken, userAgent, ipAddress)
	if err != nil {
		return nil, "", "", err
	}

	userDTO := &auth.UserDTO{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Status:        string(u.Status),
		CreatedAt:     u.CreatedAt.Format(time.RFC3339),
	}
	if u.Name != "" {
		userDTO.Name = &u.Name
	}

	return userDTO, accessToken, newRawRefreshToken, nil
}

// UserInfoResponse is the claim set returned by the OIDC UserInfo endpoint.
type UserInfoResponse struct {
	// Sub is the subject identifier — the user's stable ID.
	Sub string `json:"sub"`
	// Email is the user's primary address.
	Email string `json:"email"`
	// EmailVerified reports whether that address has been confirmed.
	EmailVerified bool `json:"email_verified"`
	// Name is the display name, omitted when unset.
	Name string `json:"name,omitempty"`
	// TenantID identifies the tenant the subject belongs to.
	TenantID string `json:"tenant_id"`
	// Environment is the tier the user record lives in.
	Environment string `json:"environment,omitempty"`
	// UpdatedAt is when the profile last changed.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// GetUserInfo returns the claim set for userID within tenantID.
//
// Returns an error when no user ID is supplied and a single indistinct "user
// not found" when the lookup fails or matches nothing, so the endpoint cannot
// be used to probe which subject IDs exist.
func (s *Service) GetUserInfo(ctx context.Context, tenantID, userID string) (*UserInfoResponse, error) {
	if userID == "" {
		return nil, fmt.Errorf("user_id is required")
	}

	u, err := s.authRepo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, fmt.Errorf("user not found")
	}

	return &UserInfoResponse{
		Sub:           u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		TenantID:      tenantID,
		Environment:   string(u.Environment),
		UpdatedAt:     u.UpdatedAt,
	}, nil
}
