/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/key_manager.go
 * Tier: Shared Package / JWKS Key Rotation & Multi-Key Storage
 *
 * Description: Multi-key JWKS data model, RSA key pair generation, 30-day rotation,
 *              7-day grace period key retention, and kid-based JWT signature verification.
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
	"strings"
	"sync"
	"time"
)

// KeyEntry represents an individual RSA signing keypair in the rotation lifecycle.
type KeyEntry struct {
	ID         string          `json:"id"`
	PrivateKey *rsa.PrivateKey `json:"-"`
	PublicKey  *rsa.PublicKey  `json:"-"`
	CreatedAt  time.Time       `json:"created_at"`
	IsActive   bool            `json:"is_active"`
}

// KeyManager manages active signing keys and retained grace-period keys.
type KeyManager struct {
	mu        sync.RWMutex
	activeKey *KeyEntry
	graceKeys []*KeyEntry
}

// NewKeyManager initializes a KeyManager with a default active RSA key.
func NewKeyManager(initialKeyID ...string) (*KeyManager, error) {
	km := &KeyManager{
		graceKeys: make([]*KeyEntry, 0),
	}

	keyID := "authn-rsa-key-v1"
	if len(initialKeyID) > 0 && initialKeyID[0] != "" {
		keyID = initialKeyID[0]
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed generating initial RSA key: %w", err)
	}

	km.activeKey = &KeyEntry{
		ID:         keyID,
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		CreatedAt:  time.Now().UTC(),
		IsActive:   true,
	}

	return km, nil
}

// RotateKey triggers a key rotation: moves the active key to grace keys and generates a new active key.
func (km *KeyManager) RotateKey(newKeyID ...string) (*KeyEntry, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	kid := fmt.Sprintf("authn-rsa-key-%d", time.Now().Unix())
	if len(newKeyID) > 0 && newKeyID[0] != "" {
		kid = newKeyID[0]
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed generating new rotated RSA key: %w", err)
	}

	if km.activeKey != nil {
		km.activeKey.IsActive = false
		km.graceKeys = append(km.graceKeys, km.activeKey)
	}

	km.activeKey = &KeyEntry{
		ID:         kid,
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		CreatedAt:  time.Now().UTC(),
		IsActive:   true,
	}

	return km.activeKey, nil
}

// GetActiveKey returns the currently active signing key.
func (km *KeyManager) GetActiveKey() *KeyEntry {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.activeKey
}

// GetPublicJWKS exports all public keys (Active + Grace Period keys) as an RFC 7517 JWKS payload.
func (km *KeyManager) GetPublicJWKS() JWKSResponse {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([]JSONWebKey, 0)

	if km.activeKey != nil && km.activeKey.PublicKey != nil {
		nBytes := km.activeKey.PublicKey.N.Bytes()
		eBytes := big.NewInt(int64(km.activeKey.PublicKey.E)).Bytes()
		keys = append(keys, JSONWebKey{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: km.activeKey.ID,
			N:   base64.RawURLEncoding.EncodeToString(nBytes),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		})
	}

	for _, gk := range km.graceKeys {
		if gk != nil && gk.PublicKey != nil {
			nBytes := gk.PublicKey.N.Bytes()
			eBytes := big.NewInt(int64(gk.PublicKey.E)).Bytes()
			keys = append(keys, JSONWebKey{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: gk.ID,
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			})
		}
	}

	return JWKSResponse{Keys: keys}
}

// SignToken signs claims using the active RSA key and embeds active kid into JWT header.
func (km *KeyManager) SignToken(claims interface{}) (string, error) {
	km.mu.RLock()
	active := km.activeKey
	km.mu.RUnlock()

	if active == nil || active.PrivateKey == nil {
		return "", fmt.Errorf("no active RSA key available for signing")
	}

	return SignIDTokenRS256(active.PrivateKey, claims, active.ID)
}

// VerifyToken verifies a JWT signature by matching its header kid against active or grace period keys.
func (km *KeyManager) VerifyToken(tokenStr string) (map[string]interface{}, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed decoding jwt header: %w", err)
	}

	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed unmarshaling jwt header: %w", err)
	}

	kid := header["kid"]
	if kid == "" {
		return nil, fmt.Errorf("missing kid in jwt header")
	}

	km.mu.RLock()
	var matchingPubKey *rsa.PublicKey
	if km.activeKey != nil && km.activeKey.ID == kid {
		matchingPubKey = km.activeKey.PublicKey
	} else {
		for _, gk := range km.graceKeys {
			if gk.ID == kid {
				matchingPubKey = gk.PublicKey
				break
			}
		}
	}
	km.mu.RUnlock()

	if matchingPubKey == nil {
		return nil, fmt.Errorf("key id '%s' not found in active or grace period JWKS", kid)
	}

	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed decoding jwt signature: %w", err)
	}

	if err := rsa.VerifyPKCS1v15(matchingPubKey, crypto.SHA256, hashed[:], sigBytes); err != nil {
		return nil, fmt.Errorf("invalid jwt signature for key id '%s': %w", kid, err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed decoding payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed unmarshaling claims: %w", err)
	}

	return claims, nil
}
