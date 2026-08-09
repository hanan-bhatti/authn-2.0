/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/jwks.go
 * Tier: Shared Package / JWKS Document Model
 *
 * The RFC 7517 JSON Web Key Set types served at the discovery endpoint, where
 * relying parties fetch the material they need to verify tokens this engine
 * issued.
 *
 * Only public values ever appear in these structures. The document is served
 * unauthenticated by design — a verifier must be able to fetch it before it
 * trusts anything — so anything placed here is public.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package jwt

// JSONWebKey is a single entry in a key set.
type JSONWebKey struct {
	// Kty is the key type: "RSA" for the ID token signing keys, "oct" for the
	// symmetric access token key.
	Kty string `json:"kty"`
	// Use marks the key's purpose; "sig" means signature verification rather
	// than encryption.
	Use string `json:"use"`
	// Alg is the algorithm this key is used with: "RS256" or "HS256".
	Alg string `json:"alg"`
	// Kid identifies the key. Token headers carry the same value so a verifier
	// can select the right entry without trying each in turn.
	Kid string `json:"kid"`
	// N is the RSA modulus, base64url-encoded, omitted for symmetric keys.
	N string `json:"n,omitempty"`
	// E is the RSA public exponent, base64url-encoded, omitted for symmetric
	// keys.
	E string `json:"e,omitempty"`
}

// JWKSResponse is the document returned by /v1/oauth/jwks.
type JWKSResponse struct {
	// Keys lists every key a verifier may need, including recently retired ones
	// whose tokens have not all expired.
	Keys []JSONWebKey `json:"keys"`
}

// GetPublicJWKS describes the symmetric access token key.
//
// The entry carries the key's identifier and algorithm but no `k` member, so no
// key material is disclosed and the document remains safe to serve publicly.
// It exists so the discovery endpoint can name the active key rather than
// returning an empty set; HS256 tokens are verified inside the engine, and an
// external party cannot verify them from this document. RSA-signed ID tokens,
// which external parties do verify, are published by KeyManager.GetPublicJWKS.
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
