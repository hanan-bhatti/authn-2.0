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

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
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
// exact redirect URIs it is permitted to use and the browser origins its
// publishable keys may be called from.
//
// env is "test" or "live". redirectURIs and corsOrigins may be empty; an empty
// CORS list leaves origin checking to the deployment-wide policy. An empty
// frontendBaseURL leaves emailed links on the deployment default. Returns the
// stored record — including schema defaults the caller did not set, such as the
// environment and timestamps — or an error if the repository is unavailable or
// the write fails (a duplicate client_id surfaces as an *ent.ConstraintError).
func (s *Service) CreateClientApplication(ctx context.Context, id, tenantID, name, env string, redirectURIs, corsOrigins []string, frontendBaseURL string) (*ent.Application, error) {
	if s.authRepo == nil {
		return nil, fmt.Errorf("auth repository uninitialized")
	}
	return s.authRepo.CreateApplication(ctx, id, tenantID, name, env, redirectURIs, corsOrigins, frontendBaseURL)
}

// ListClientApplications returns the caller's tenant's applications. The tenant
// is taken from the request context by the privacy interceptor, not passed in.
func (s *Service) ListClientApplications(ctx context.Context) ([]*ent.Application, error) {
	if s.authRepo == nil {
		return nil, fmt.Errorf("auth repository uninitialized")
	}
	return s.authRepo.ListApplications(ctx)
}

// GetClientApplication returns one application within the caller's tenant, or
// nil when none matches — including when the ID belongs to another tenant.
func (s *Service) GetClientApplication(ctx context.Context, id string) (*ent.Application, error) {
	if s.authRepo == nil {
		return nil, fmt.Errorf("auth repository uninitialized")
	}
	return s.authRepo.GetApplicationByIDScoped(ctx, id)
}

// UpdateClientApplication applies a partial update within the caller's tenant. A
// nil field is left unchanged. Returns nil when the application does not exist
// in this tenant.
func (s *Service) UpdateClientApplication(ctx context.Context, id string, name *string, redirectURIs, corsOrigins *[]string, frontendBaseURL *string) (*ent.Application, error) {
	if s.authRepo == nil {
		return nil, fmt.Errorf("auth repository uninitialized")
	}
	return s.authRepo.UpdateApplication(ctx, id, name, redirectURIs, corsOrigins, frontendBaseURL)
}

// DeleteClientApplication removes an application within the caller's tenant,
// reporting whether one was deleted.
func (s *Service) DeleteClientApplication(ctx context.Context, id string) (bool, error) {
	if s.authRepo == nil {
		return false, fmt.Errorf("auth repository uninitialized")
	}
	return s.authRepo.DeleteApplication(ctx, id)
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
