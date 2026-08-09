/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/model.go
 * Tier: Internal Feature Package / OAuth2 & OIDC Models
 *
 * Description: Wire types for the OAuth2 and OpenID Connect surface — the
 *              discovery document, the in-flight authorization code, the token
 *              response, ID token claims, and PKCE verification.
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

// OIDCDiscoveryConfig is the RFC 8414 metadata document served at
// /.well-known/openid-configuration. Relying parties read it to locate the
// endpoints and learn which algorithms and grants are on offer.
type OIDCDiscoveryConfig struct {
	// Issuer is the identifier that appears in the `iss` claim of every token.
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is where the browser starts the code flow.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is where codes and refresh tokens are redeemed.
	TokenEndpoint string `json:"token_endpoint"`
	// UserinfoEndpoint returns claims for a bearer access token.
	UserinfoEndpoint string `json:"userinfo_endpoint"`
	// JwksURI publishes the public keys that verify issued tokens.
	JwksURI string `json:"jwks_uri"`
	// ResponseTypesSupported lists the supported response types.
	ResponseTypesSupported []string `json:"response_types_supported"`
	// SubjectTypesSupported lists the supported subject identifier types.
	SubjectTypesSupported []string `json:"subject_types_supported"`
	// IDTokenSigningAlgValuesSupported lists the ID token signing algorithms.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// ScopesSupported lists the scopes a client may request.
	ScopesSupported []string `json:"scopes_supported"`
	// TokenEndpointAuthMethodsSupported lists accepted client authentication
	// methods at the token endpoint.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// CodeChallengeMethodsSupported lists the accepted PKCE methods. Advertising
	// S256 alone tells clients that "plain" will be refused.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// ClaimsSupported lists the claims that may appear in issued tokens.
	ClaimsSupported []string `json:"claims_supported"`
	// GrantTypesSupported lists the supported grant types.
	GrantTypesSupported []string `json:"grant_types_supported"`
}

// AuthorizationCode is an RFC 6749 authorization code held between the
// authorization request and the token exchange. Every field recorded here is
// re-checked at redemption, which is what binds the code to one client, one
// destination and one PKCE secret.
type AuthorizationCode struct {
	// Code is the opaque value handed to the client.
	Code string `json:"code"`
	// ClientID is the application the code was issued to.
	ClientID string `json:"client_id"`
	// UserID is the authenticated subject the code speaks for. Claims are read
	// from this ID at redemption, never from the redeeming request.
	UserID string `json:"user_id"`
	// TenantID scopes the resulting tokens.
	TenantID string `json:"tenant_id"`
	// RedirectURI is the destination named at authorization time.
	RedirectURI string `json:"redirect_uri"`
	// CodeChallenge is the PKCE challenge the verifier must hash to.
	CodeChallenge string `json:"code_challenge"`
	// CodeChallengeMethod is the PKCE transform, "S256".
	CodeChallengeMethod string `json:"code_challenge_method"`
	// Scope is the scope granted at authorization time.
	Scope string `json:"scope"`
	// ExpiresAt is when the code stops being redeemable.
	ExpiresAt time.Time `json:"expires_at"`
}

// OAuth2TokenResponse is the body returned by the token endpoint.
type OAuth2TokenResponse struct {
	// AccessToken authenticates subsequent API calls.
	AccessToken string `json:"access_token"`
	// TokenType is always "Bearer".
	TokenType string `json:"token_type" example:"Bearer"`
	// ExpiresIn is the access token lifetime in seconds.
	ExpiresIn int `json:"expires_in" example:"900"`
	// RefreshToken is present on the refresh grant.
	RefreshToken string `json:"refresh_token,omitempty"`
	// IDToken is the signed OIDC identity assertion.
	IDToken string `json:"id_token,omitempty"`
	// Scope is the scope actually granted.
	Scope string `json:"scope,omitempty" example:"openid profile email"`
}

// IDTokenClaims is the OIDC ID token payload, signed with RS256 so a relying
// party can verify it against the published JWKS without calling back here.
type IDTokenClaims struct {
	// Issuer identifies the engine that signed the token.
	Issuer string `json:"iss"`
	// Subject is the user's stable identifier.
	Subject string `json:"sub"`
	// Audience is the client_id the token was minted for. A relying party must
	// reject a token whose audience is not itself.
	Audience string `json:"aud"`
	// TenantID scopes the subject to a tenant.
	TenantID string `json:"tenant_id"`
	// Email is the subject's primary address.
	Email string `json:"email"`
	// EmailVerified reports whether that address is confirmed.
	EmailVerified bool `json:"email_verified"`
	// Name is the display name, omitted when unset.
	Name string `json:"name,omitempty"`
	// IssuedAt is the signing time, in Unix seconds.
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is the expiry time, in Unix seconds.
	ExpiresAt int64 `json:"exp"`
	// Nonce echoes the client's replay nonce when one was supplied.
	Nonce string `json:"nonce,omitempty"`
	// AuthTime is when the subject actually authenticated, in Unix seconds.
	AuthTime int64 `json:"auth_time"`
}

// VerifyPKCE reports whether verifier satisfies challenge under the RFC 7636
// transform named by method.
//
// S256 compares the base64url-encoded SHA-256 of the verifier against the
// challenge, ignoring padding differences because the encoding is defined
// without padding but not every client omits it.
//
// "plain" compares the two directly and offers no protection against an
// attacker who observed the authorization request; the authorization endpoint
// refuses it before a code is ever issued. Any other method returns false.
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
