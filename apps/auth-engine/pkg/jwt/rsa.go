/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/rsa.go
 * Tier: Shared Package / Cryptographic RSA Key Signer & Persistence
 *
 * Description: RS256 (RSA PKCS#1 v1.5 with SHA-256) key generation, PEM file persistence,
 *              swappable KeyStore interface, token signing, and public JWKS exporter.
 *
 * Architecture Note:
 *   - For local/dev environments, FileKeyStore persists RSA private keys in PKCS#1 PEM format to disk.
 *   - Production Note: In multi-replica cloud deployments (Kubernetes/ECS), the KeyStore interface
 *     should be backed by PostgreSQL or a KMS/Secrets Manager (AWS KMS, HashiCorp Vault, GCP Secret Manager)
 *     so that key rotation and token verification remain consistent across all running instances.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
)

var (
	globalRSALock sync.RWMutex
	globalRSAKey  *rsa.PrivateKey
)

// KeyStore abstracts RSA private key persistence across file, database, or KMS backends.
type KeyStore interface {
	LoadKey() (*rsa.PrivateKey, error)
	SaveKey(key *rsa.PrivateKey) error
}

// FileKeyStore implements file-backed RSA private key persistence on disk.
type FileKeyStore struct {
	FilePath string
}

// LoadKey reads and parses a PKCS#1 or PKCS#8 RSA private key from PEM file storage.
func (f *FileKeyStore) LoadKey() (*rsa.PrivateKey, error) {
	if f.FilePath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(f.FilePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed reading RSA key file %s: %w", f.FilePath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM block from %s", f.FilePath)
	}

	// Try PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8
	if keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := keyInterface.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}

	return nil, fmt.Errorf("unrecognized or invalid RSA private key format in %s", f.FilePath)
}

// SaveKey persists an RSA private key to disk in PKCS#1 PEM format with 0600 permissions.
func (f *FileKeyStore) SaveKey(key *rsa.PrivateKey) error {
	if f.FilePath == "" || key == nil {
		return nil
	}

	dir := filepath.Dir(f.FilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed creating directory %s for RSA key: %w", dir, err)
	}

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(f.FilePath, pemBytes, 0600); err != nil {
		return fmt.Errorf("failed writing RSA private key to %s: %w", f.FilePath, err)
	}

	return nil
}

// GetOrGenerateRSAPrivateKey returns a persisted, cached, or newly generated 2048-bit RSA private key.
func GetOrGenerateRSAPrivateKey(keyPath ...string) (*rsa.PrivateKey, error) {
	path := ".keys/rsa_private.pem"
	if len(keyPath) > 0 && keyPath[0] != "" {
		path = keyPath[0]
	} else if envPath := os.Getenv("AUTHN_RSA_KEY_PATH"); envPath != "" {
		path = envPath
	}

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

	store := &FileKeyStore{FilePath: path}

	// 1. Check for existing persisted key
	existingKey, err := store.LoadKey()
	if err != nil {
		return nil, fmt.Errorf("failed loading persisted RSA key: %w", err)
	}
	if existingKey != nil {
		globalRSAKey = existingKey
		return globalRSAKey, nil
	}

	// 2. Generate new 2048-bit RSA keypair if none exists
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed generating RSA 2048 keypair: %w", err)
	}

	// 3. Persist generated key to disk
	if err := store.SaveKey(newKey); err != nil {
		return nil, fmt.Errorf("failed persisting RSA key to disk: %w", err)
	}

	globalRSAKey = newKey
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
