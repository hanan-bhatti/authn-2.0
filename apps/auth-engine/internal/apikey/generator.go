/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/generator.go
 * Tier: Internal Feature Package / API Key Generation
 *
 * Mints API keys and derives the peppered hashes stored in their place.
 *
 * A key's prefix states what it is — publishable or secret, test or live — so
 * that a key pasted into the wrong place is recognisable on sight, and so that
 * secret-scanning tools can match the shape and flag a leak before it is used.
 *
 * Only the hash is ever stored. The pepper mixed into it lives in configuration
 * rather than the database, so an attacker holding a database dump alone cannot
 * test candidate keys offline: they would have to guess a 256-bit key and the
 * pepper together.
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

// KeyType is an API key's privilege scope.
type KeyType string

const (
	// TypePublishable marks a key safe to ship in a browser or mobile client.
	// It authenticates the application, not an operator, and grants only the
	// endpoints a public client needs.
	TypePublishable KeyType = "publishable"
	// TypeSecret marks a key that must stay server-side. It carries
	// administrative authority over its application.
	TypeSecret KeyType = "secret"
)

// keyRandomBytes is the entropy behind every key, in bytes. At 256 bits, a key
// is not reachable by guessing regardless of how fast an attacker can test.
const keyRandomBytes = 32

// GeneratedApiKey is a freshly minted key, carrying both the value shown to the
// operator and the value written to the database.
type GeneratedApiKey struct {
	// ID is the key's public identifier.
	ID string `json:"id"`
	// Type is the key's privilege scope.
	Type KeyType `json:"type"`
	// Prefix is the leading marker of RawKey, stored separately so a key can be
	// listed and recognised without retaining the key itself.
	Prefix string `json:"prefix"`
	// RawKey is the usable key. It exists only in the response to the call that
	// created it: nothing persists it, and it cannot be recovered afterwards.
	RawKey string `json:"raw_key"`
	// KeyHash is the peppered HMAC-SHA256 digest that is stored and looked up.
	KeyHash string `json:"key_hash"`
}

// GenerateApiKey creates a key of the given scope and environment, returning it
// alongside the hash to persist.
//
// The environment is anything other than "live" treated as test, so an
// unrecognised value produces a test key rather than a live one — the safe
// direction to fail.
//
// Returns an error only when the system random source fails. That is fatal
// rather than retryable: a key drawn from a degraded source could be
// predictable, and a predictable API key is a bypass of every check that
// depends on it.
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

	randomBytes := make([]byte, keyRandomBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed generating random bytes for api key: %w", err)
	}

	rawKey := prefix + hex.EncodeToString(randomBytes)

	// HMAC rather than a bare hash: the pepper is a key, not a salt, and it is
	// what makes a stolen database insufficient to verify a guessed key. A
	// per-key salt would be stored beside the hash and would not help here.
	//
	// No password-style stretching is applied, and none is needed — a 256-bit
	// random key has nothing to brute force, and stretching would add cost to
	// every authenticated request instead.
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
