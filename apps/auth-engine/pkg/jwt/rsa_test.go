package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRS256_SignAndExportJWKS(t *testing.T) {
	key, err := GetOrGenerateRSAPrivateKey()
	if err != nil {
		t.Fatalf("failed generating RSA key: %v", err)
	}

	claims := map[string]interface{}{
		"iss": "http://localhost:8080",
		"sub": "usr_test123",
	}

	tokenStr, err := SignIDTokenRS256(key, claims, "key_v1")
	if err != nil {
		t.Fatalf("failed signing token with RS256: %v", err)
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JWT token string, got %d", len(parts))
	}

	// Verify signature using RSA Public Key
	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed decoding signature base64: %v", err)
	}

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		t.Fatalf("RSA public key signature verification failed: %v", err)
	}

	// Verify JWKS Export
	jwks := ExportRSAPublicJWKS(&key.PublicKey, "key_v1")
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(jwks.Keys))
	}

	k := jwks.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" || k.Kid != "key_v1" {
		t.Fatalf("invalid JWKS key metadata: %+v", k)
	}
	if k.N == "" || k.E == "" {
		t.Fatalf("JWKS key missing Modulus N or Exponent E")
	}
}
