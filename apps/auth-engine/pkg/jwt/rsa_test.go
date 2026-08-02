package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRS256_SignAndExportJWKS(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "jwt_test_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test_rsa.pem")

	// 1. Initial Generation & Persistence
	key1, err := GetOrGenerateRSAPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("failed generating RSA key: %v", err)
	}

	claims := map[string]interface{}{
		"iss": "http://localhost:8080",
		"sub": "usr_test123",
	}

	tokenStr, err := SignIDTokenRS256(key1, claims, "key_v1")
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

	err = rsa.VerifyPKCS1v15(&key1.PublicKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		t.Fatalf("RSA public key signature verification failed: %v", err)
	}

	// 2. Reset global cache and reload from disk
	globalRSALock.Lock()
	globalRSAKey = nil
	globalRSALock.Unlock()

	store := &FileKeyStore{FilePath: keyPath}
	key2, err := store.LoadKey()
	if err != nil {
		t.Fatalf("failed loading key from disk: %v", err)
	}
	if key2 == nil {
		t.Fatalf("expected loaded key from disk, got nil")
	}

	// Verify Modulus 'n' and Exponent 'e' match 100% across reload
	jwks1 := ExportRSAPublicJWKS(&key1.PublicKey, "key_v1")
	jwks2 := ExportRSAPublicJWKS(&key2.PublicKey, "key_v1")

	if jwks1.Keys[0].N != jwks2.Keys[0].N {
		t.Fatalf("RSA public key Modulus N mismatch across server restart!\nBefore: %s\nAfter:  %s", jwks1.Keys[0].N, jwks2.Keys[0].N)
	}
	if jwks1.Keys[0].E != jwks2.Keys[0].E {
		t.Fatalf("RSA public key Exponent E mismatch across server restart!")
	}
}
