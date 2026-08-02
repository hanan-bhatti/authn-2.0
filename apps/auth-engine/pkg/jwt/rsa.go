/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/rsa.go
 * Tier: Shared Package / Cryptographic RSA Key Signer
 *
 * Description: RS256 (RSA PKCS#1 v1.5 with SHA-256) key generation, token signing,
 *              and public JWKS key component exporter (Modulus 'n', Exponent 'e').
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
)

var (
	globalRSALock sync.RWMutex
	globalRSAKey  *rsa.PrivateKey
)

// GetOrGenerateRSAPrivateKey returns a cached or newly generated 2048-bit RSA private key.
func GetOrGenerateRSAPrivateKey() (*rsa.PrivateKey, error) {
	globalRSALock.RLock()
	if globalRSAKey != nil {
		defer globalRSALock.RUnlock()
		return globalRSAKey, nil
	}
	globalRSALock.RUnlock()

	globalRSALock.Lock()
	defer globalRSALock.Unlock()

	if globalRSAKey != nil {
		return globalRSAKey, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed generating RSA 2048 keypair: %w", err)
	}

	globalRSAKey = key
	return globalRSAKey, nil
}

// SignIDTokenRS256 signs ID token claims using RS256 (RSA SHA-256 private key).
func SignIDTokenRS256(privKey *rsa.PrivateKey, claims interface{}, keyID string) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": keyID,
	})
	if err != nil {
		return "", fmt.Errorf("failed marshaling RS256 jwt header: %w", err)
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed marshaling RS256 jwt claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	hashed := sha256.Sum256([]byte(signingInput))

	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed signing token with RSA private key: %w", err)
	}

	signature := base64.RawURLEncoding.EncodeToString(signatureBytes)
	return signingInput + "." + signature, nil
}

// ExportRSAPublicJWKS extracts public key components (Modulus N, Exponent E) for JWKS endpoint.
func ExportRSAPublicJWKS(pubKey *rsa.PublicKey, keyID string) JWKSResponse {
	nBytes := pubKey.N.Bytes()
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()

	return JWKSResponse{
		Keys: []JSONWebKey{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: keyID,
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
}
