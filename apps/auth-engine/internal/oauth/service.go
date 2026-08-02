/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/service.go
 * Tier: Internal Feature Package / OAuth2 & OIDC Service
 *
 * Description: Core business logic layer for OpenID Connect (OIDC) discovery,
 *              PKCE authorization code generation, and JWT ID token signing.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Service provides business logic for OAuth2 and OIDC flows.
type Service struct {
	repo *Repository
	cfg  *config.EnvConfig
}

// NewService constructs a new OAuth2 Service instance.
func NewService(repo *Repository, cfg *config.EnvConfig) *Service {
	return &Service{
		repo: repo,
		cfg:  cfg,
	}
}

// GetDiscoveryMetadata returns standard OIDC Discovery configurations.
func (s *Service) GetDiscoveryMetadata(issuer string) OIDCDiscoveryConfig {
	if issuer == "" {
		issuer = s.cfg.Issuer
	}
	if issuer == "" {
		issuer = "http://localhost:8080"
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
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
		ClaimsSupported:                   []string{"iss", "sub", "aud", "exp", "iat", "email", "name", "tenant_id"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
	}
}

// IssueAuthorizationCode generates a 10-minute ephemeral authorization code for PKCE flows.
func (s *Service) IssueAuthorizationCode(ctx context.Context, clientID string, userID string, tenantID string, redirectURI string, codeChallenge string, method string, scope string) (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed generating random code: %w", err)
	}

	codeStr := "ac_" + hex.EncodeToString(bytes)
	authCode := AuthorizationCode{
		Code:                codeStr,
		ClientID:            clientID,
		UserID:              userID,
		TenantID:            tenantID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: method,
		Scope:               scope,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := s.repo.SaveAuthorizationCode(ctx, authCode); err != nil {
		return "", err
	}

	return codeStr, nil
}

// ExchangeCodeForTokens consumes an authorization code, verifies PKCE code_verifier, and issues signed ID & Access tokens.
func (s *Service) ExchangeCodeForTokens(ctx context.Context, codeStr string, clientID string, redirectURI string, codeVerifier string, email string, name string) (*OAuth2TokenResponse, error) {
	authCode, err := s.repo.ConsumeAuthorizationCode(ctx, codeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code: %w", err)
	}

	// Validate client_id and redirect_uri match original authorization request
	if authCode.ClientID != "" && authCode.ClientID != clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}
	if authCode.RedirectURI != "" && authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	// PKCE Verification
	if authCode.CodeChallenge != "" {
		if !VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("invalid PKCE code_verifier")
		}
	}

	// Issue Access Token
	accessToken, err := jwtpkg.IssueAccessToken(authCode.UserID, authCode.TenantID, "test", email, name, s.cfg.AuthnEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed issuing access token: %w", err)
	}

	// Issue Signed OIDC ID Token with RS256 (RSA Private Key)
	rsaPrivKey, err := jwtpkg.GetOrGenerateRSAPrivateKey()
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
		ExpiresAt:     now.Add(1 * time.Hour).Unix(),
		AuthTime:      now.Unix(),
	}

	idTokenStr, err := jwtpkg.SignIDTokenRS256(rsaPrivKey, idClaims, s.cfg.AuthnKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed signing ID token with RS256: %w", err)
	}

	return &OAuth2TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   900, // 15 minutes
		IDToken:     idTokenStr,
		Scope:       "openid profile email",
	}, nil
}
