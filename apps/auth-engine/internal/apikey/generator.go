/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/generator.go
 * Tier: Internal Feature Package / API Key Generation
 *
 * Description: Generates prefix-scoped API keys (pk_test_..., pk_live_...,
 *              sk_test_..., sk_live_...) with 32 cryptographically secure random bytes
 *              and computes peppered HMAC-SHA256 hashes for database persistence.
 *
 * Security Notice:
 *   - Plain text secret API keys (sk_...) are returned ONLY ONCE upon creation.
 *   - Database stores strictly peppered HMAC-SHA256 hashes.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package apikey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// KeyType defines API key access scope ("publishable" vs "secret").
type KeyType string

const (
	TypePublishable KeyType = "publishable"
	TypeSecret      KeyType = "secret"
)

// GeneratedApiKey holds both the raw API key (for user display) and its peppered hash.
type GeneratedApiKey struct {
	ID        string  `json:"id"`
	Type      KeyType `json:"type"`
	Prefix    string  `json:"prefix"`
	RawKey    string  `json:"raw_key"`   // Only populated during initial creation
	KeyHash   string  `json:"key_hash"`  // Peppered HMAC-SHA256 hash for database storage
}

// GenerateApiKey creates a new API key with the appropriate prefix and peppered hash.
//
// Parameters:
//   - keyType: TypeSecret or TypePublishable.
//   - environment: "test" or "live".
//   - pepper: Server-side HMAC pepper string (`AUTHN_API_KEY_PEPPER`).
//
// Returns:
//   - *GeneratedApiKey: Generated key struct.
//   - error: Non-nil if random byte generation fails.
func GenerateApiKey(keyType KeyType, environment string, pepper string) (*GeneratedApiKey, error) {
	var prefix string
	if keyType == TypePublishable {
		if environment == "live" {
			prefix = "pk_live_"
		} else {
			prefix = "pk_test_"
		}
	} else {
		if environment == "live" {
			prefix = "sk_live_"
		} else {
			prefix = "sk_test_"
		}
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed generating random bytes for api key: %w", err)
	}

	rawKey := prefix + hex.EncodeToString(randomBytes)

	// Compute peppered HMAC-SHA256 hash
	h := hmac.New(sha256.New, []byte(pepper))
	h.Write([]byte(rawKey))
	keyHash := hex.EncodeToString(h.Sum(nil))

	return &GeneratedApiKey{
		Type:    keyType,
		Prefix:  prefix,
		RawKey:  rawKey,
		KeyHash: keyHash,
	}, nil
}
