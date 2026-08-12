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
