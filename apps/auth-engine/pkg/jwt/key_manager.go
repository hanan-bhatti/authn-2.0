/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/key_manager.go
 * Tier: Shared Package / Signing Key Rotation
 *
 * Holds the active RS256 signing key alongside the keys it replaced, so that
 * rotating a key does not invalidate tokens signed a moment earlier.
 *
 * Rotation has an unavoidable overlap. Tokens signed by the outgoing key stay
 * in circulation until they expire, and relying parties cache the key set for
 * a while longer, so a key must remain published after it stops signing. The
 * active key signs; active and retired keys alike verify and appear in JWKS,
 * with the header's `kid` selecting between them.
 *
 * Retention is bounded by the caller, not by this type. Rotation happens when
 * RotateKey is called and retired keys are held until the process exits;
 * nothing here expires a key on a schedule. Keys are generated in memory and
 * are not persisted, so every restart begins with a new key set — which makes
 * this suitable for a single instance and not for several replicas that must
 * publish the same keys.
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

// defaultInitialKeyID names the first key when the caller supplies no ID.
const defaultInitialKeyID = "authn-rsa-key-v1"

// KeyEntry is one signing keypair and its place in the rotation lifecycle.
type KeyEntry struct {
	// ID is the `kid` published in JWKS and stamped into token headers. It must
	// be unique across the key set; a repeated ID makes verification pick a key
	// arbitrarily.
	ID string `json:"id"`
	// PrivateKey signs tokens. It is excluded from JSON so that marshalling a
	// KeyEntry — for a log line or a debug endpoint — cannot leak it.
	PrivateKey *rsa.PrivateKey `json:"-"`
	// PublicKey verifies tokens and is what JWKS publishes. Also excluded from
	// JSON, since JWKS output is built explicitly rather than by marshalling
	// this struct.
	PublicKey *rsa.PublicKey `json:"-"`
	// CreatedAt records when the key was generated, so an operator can tell how
	// long a retired key has been lingering in the key set.
	CreatedAt time.Time `json:"created_at"`
	// IsActive marks the key currently used for signing. Exactly one key in a
	// KeyManager has this set.
	IsActive bool `json:"is_active"`
}

// KeyManager owns the active signing key and the retired keys still trusted for
// verification. It is safe for concurrent use.
type KeyManager struct {
	// mu guards activeKey and graceKeys.
	mu sync.RWMutex
	// activeKey signs all new tokens.
	activeKey *KeyEntry
	// graceKeys are previously active keys, retained so tokens they signed
	// still verify. Append-only for the life of the process.
	graceKeys []*KeyEntry
}

// NewKeyManager creates a manager with one freshly generated active key.
//
// initialKeyID is optional; the first non-empty value is used, otherwise
// defaultInitialKeyID. Pass the configured key ID so that the `kid` in issued
// tokens matches what the deployment advertises.
//
// Returns an error if key generation fails, which means the system random
// source is unavailable and the engine cannot sign anything.
func NewKeyManager(initialKeyID ...string) (*KeyManager, error) {
	km := &KeyManager{
		graceKeys: make([]*KeyEntry, 0),
	}

	keyID := defaultInitialKeyID
	if len(initialKeyID) > 0 && initialKeyID[0] != "" {
		keyID = initialKeyID[0]
	}

	privKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
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

// RotateKey generates a new active key and retires the current one into the
// grace set, returning the new key.
//
// newKeyID is optional; without it the ID is derived from the current Unix
// second. Supply an explicit ID when the deployment needs a predictable one,
// since two rotations within the same second would otherwise collide.
//
// Returns an error if key generation fails, in which case the existing active
// key is left untouched and signing continues uninterrupted.
func (km *KeyManager) RotateKey(newKeyID ...string) (*KeyEntry, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	kid := fmt.Sprintf("authn-rsa-key-%d", time.Now().Unix())
	if len(newKeyID) > 0 && newKeyID[0] != "" {
		kid = newKeyID[0]
	}

	// Generate before mutating anything, so a failure leaves the manager in its
	// previous working state rather than with no active key.
	privKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
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

// GetActiveKey returns the key currently used for signing, or nil if the
// manager holds none.
func (km *KeyManager) GetActiveKey() *KeyEntry {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.activeKey
}

// GetPublicJWKS returns every public key a relying party may need: the active
// key first, then the retired ones.
//
// Retired keys must stay in this document. Dropping a key the moment it stops
// signing would break verification for every token it signed that has not yet
// expired.
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

// SignToken signs claims with the active key, stamping its ID into the header's
// `kid`.
//
// Returns an error when no active key is available, or when signing fails.
func (km *KeyManager) SignToken(claims interface{}) (string, error) {
	km.mu.RLock()
	active := km.activeKey
	km.mu.RUnlock()

	if active == nil || active.PrivateKey == nil {
		return "", fmt.Errorf("no active RSA key available for signing")
	}

	return SignIDTokenRS256(active.PrivateKey, claims, active.ID)
}

// VerifyToken checks a token's RS256 signature against whichever held key its
// `kid` names, and returns the decoded claims.
//
// It verifies the signature only. Expiry, issuer and audience are not checked
// and the claims are returned raw, so a caller that treats a nil error as
// "token is valid" will accept expired tokens. Validate the standard claims
// after this returns.
//
// Returns an error when the token is malformed, when its header carries no
// `kid`, when no held key matches that `kid`, or when the signature does not
// verify. A missing `kid` is rejected rather than falling back to the active
// key: trying keys until one works would let a token outlive the rotation it
// was meant to be retired by.
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

	// The `kid` selects a key; it never supplies one. Only keys this manager
	// generated are consulted, so a forged header can at worst name a key that
	// does not exist.
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
