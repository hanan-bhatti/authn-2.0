/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/argon2.go
 * Tier: Shared Package / Cryptography Utilities
 *
 * Description: RFC 9106 Argon2id password hashing and verification utility.
 *
 * Security Notice:
 *   - Enforces RFC 9106 baseline: t=3 iterations, m=64MB (65536 KB), p=4 threads.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// DummyArgon2idHash is a validly formatted Argon2id hash used during authentication
// when a user is not found, ensuring constant-time CPU computation (~160ms) to prevent
// timing-based user enumeration attacks.
const DummyArgon2idHash = "$argon2id$v=19$m=65536,t=3,p=4$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"



// HashPasswordArgon2id generates an RFC 9106 Argon2id password hash string.
//
// Parameters:
//   - password: Plain text password string.
//
// Returns:
//   - string: Formatted Argon2id hash string ($argon2id$v=19$m=65536,t=3,p=4$...$).
//   - error: Non-nil if random salt generation fails.
func HashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed generating random salt: %w", err)
	}

	// RFC 9106 Argon2id baseline: t=3 iterations, m=64MB (65536 KB), p=4 threads
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	encoded := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPasswordArgon2id compares a plain text password against an Argon2id hash string.
//
// Parameters:
//   - password: Plain text password string.
//   - encodedHash: Stored Argon2id hash string.
//
// Returns:
//   - bool: True if password matches stored hash, false otherwise.
func VerifyPasswordArgon2id(password string, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	salt, err := hex.DecodeString(parts[4])
	if err != nil {
		return false
	}

	targetHash, err := hex.DecodeString(parts[5])
	if err != nil {
		return false
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(hash, targetHash) == 1
}
