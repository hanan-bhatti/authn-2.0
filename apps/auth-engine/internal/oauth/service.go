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

// AccessTokenTTLResolver supplies the access-token lifetime a tenant has chosen.
//
// It is an interface so this package does not depend on the settings cache, and so
// tests can fix a lifetime without a database. authcookie.Writer satisfies it.
type AccessTokenTTLResolver interface {
	// AccessTokenTTL returns the lifetime for one of the tenant's environments,
	// already bounded by the deployment's ceiling. It does not fail: this is called
	// on the token-exchange path, where an error would refuse a valid grant, so
	// implementations fall back to the deployment default.
	AccessTokenTTL(ctx context.Context, tenantID, environment string) time.Duration
}

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
	// accessTTL supplies the tenant's chosen access-token lifetime. May be nil, in
	// which case every tenant gets the deployment default; see accessTokenTTL.
	accessTTL AccessTokenTTLResolver
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

// WithAccessTokenTTLResolver points token issuance at the tenant's configured
// access-token lifetime and returns the service for chaining.
//
// A separate method rather than a constructor parameter, so the tests that build
// this service need no settings cache standing behind them.
func (s *Service) WithAccessTokenTTLResolver(r AccessTokenTTLResolver) *Service {
	s.accessTTL = r
	return s
}

// accessTokenTTL returns the access token lifetime for tenantID in environment,
// preferring the tenant's own setting over the deployment default.
//
// A nil resolver falls back to the deployment default, which is the right
// behaviour for a deployment that has not wired one rather than a reason to refuse
// a valid grant.
func (s *Service) accessTokenTTL(ctx context.Context, tenantID, environment string) time.Duration {
	if s.accessTTL != nil {
		return s.accessTTL.AccessTokenTTL(ctx, tenantID, environment)
	}
	if s.cfg == nil {
		return 0
	}
	return s.cfg.AccessTokenTTLFor(environment)
}

// accessTokenExpiresIn returns the access token lifetime for tenantID in
// environment in whole seconds, for the `expires_in` field of a token response.
//
// It resolves the lifetime through accessTokenTTL, the same helper the signer is
// handed, so the number advertised here and the `exp` stamped into the token are
// derived from one setting and cannot drift apart — including where the tenant has
// chosen one and where the test-environment ceiling shortens it.
func (s *Service) accessTokenExpiresIn(ctx context.Context, tenantID, environment string) int {
	ttl := s.accessTokenTTL(ctx, tenantID, environment)
	if ttl <= 0 {
		ttl = s.cfg.ClampAccessTokenTTL(environment, jwtpkg.AccessTokenTTL())
	}
	return int(ttl.Seconds())
}
