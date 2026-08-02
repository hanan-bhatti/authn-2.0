/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/jwks.go
 * Tier: Shared Package / Cryptographic Signer & JWKS
 *
 * Description: Implements RFC 7517 compliant JSON Web Key Set (JWKS) generators
 *              and public key metadata representations for OIDC token verification.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package jwt

// JSONWebKey represents an RFC 7517 JSON Web Key structure.
type JSONWebKey struct {
	Kty string `json:"kty"` // Key Type ("oct" for symmetric, "RSA" for asymmetric)
	Use string `json:"use"` // Key Use ("sig" for signature verification)
	Alg string `json:"alg"` // Algorithm ("HS256" or "RS256")
	Kid string `json:"kid"` // Key ID
	N   string `json:"n,omitempty"` // RSA Modulus (base64url)
	E   string `json:"e,omitempty"` // RSA Exponent (base64url)
}

// JWKSResponse defines the standard payload returned by /v1/oauth/jwks.
type JWKSResponse struct {
	Keys []JSONWebKey `json:"keys"`
}

// GetPublicJWKS generates the JWKS payload for public key verification.
func GetPublicJWKS(keyID string) JWKSResponse {
	return JWKSResponse{
		Keys: []JSONWebKey{
			{
				Kty: "oct",
				Use: "sig",
				Alg: "HS256",
				Kid: keyID,
			},
		},
	}
}
