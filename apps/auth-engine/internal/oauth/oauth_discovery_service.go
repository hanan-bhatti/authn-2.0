/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/oauth_discovery_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: OIDC discovery document generation, JWKS publication/rotation, and client application registration/validation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"context"
	"fmt"

	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

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
