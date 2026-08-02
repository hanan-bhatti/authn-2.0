/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/model.go
 * Tier: Internal Feature Package / OAuth2 & OIDC Models
 *
 * Description: OpenID Connect Discovery configurations, OAuth2 Authorization Code,
 *              PKCE verifiers, and Token Response payloads.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

// OIDCDiscoveryConfig defines RFC 8414 OpenID Connect Discovery metadata.
type OIDCDiscoveryConfig struct {
	Issuer                                string   `json:"issuer"`
	AuthorizationEndpoint                 string   `json:"authorization_endpoint"`
	TokenEndpoint                         string   `json:"token_endpoint"`
	UserinfoEndpoint                      string   `json:"userinfo_endpoint"`
	JwksURI                               string   `json:"jwks_uri"`
	ResponseTypesSupported                []string `json:"response_types_supported"`
	SubjectTypesSupported                 []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported      []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                       []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported     []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported         []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                       []string `json:"claims_supported"`
	GrantTypesSupported                   []string `json:"grant_types_supported"`
}

// AuthorizationCode represents an ephemeral RFC 6749 authorization code.
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	TenantID            string    `json:"tenant_id"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Scope               string    `json:"scope"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// OAuth2TokenResponse defines the standard OAuth2 token exchange response.
type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int    `json:"expires_in" example:"900"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty" example:"openid profile email"`
}

// IDTokenClaims defines standard OIDC ID token claims.
type IDTokenClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	TenantID          string `json:"tenant_id"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name,omitempty"`
	IssuedAt          int64  `json:"iat"`
	ExpiresAt         int64  `json:"exp"`
	Nonce             string `json:"nonce,omitempty"`
	AuthTime          int64  `json:"auth_time"`
}

// VerifyPKCE validates an unhashed code_verifier against a code_challenge using RFC 7636 rules.
func VerifyPKCE(verifier string, challenge string, method string) bool {
	if method == "plain" || method == "" {
		return verifier == challenge
	}

	if method == "S256" {
		h := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(h[:])
		cleanChallenge := strings.TrimRight(challenge, "=")
		cleanEncoded := strings.TrimRight(encoded, "=")
		return cleanEncoded == cleanChallenge
	}

	return false
}
