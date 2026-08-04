/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/sss.go
 * Tier: Internal Feature Package / Cryptographic SSS Service
 *
 * Description: Wrapper for Shamir's Secret Sharing (SSS) algorithms over GF(2^8). Provides
 *              flexible majority-of-N threshold calculation, zeroization of memory buffers,
 *              and secret reconstruction verification.
 *
 * Security Notice:
 *   - Raw secrets and shares MUST be zeroized immediately after computation.
 *   - Server stores ONLY SHA-256 hashes for share/secret verification.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto/shamir"
)

var (
	ErrInvalidGuardianCount = errors.New("guardian count N must be between 1 and 5")
	ErrInvalidShareCount    = errors.New("insufficient shares to meet threshold k")
	ErrReconstructionFailed = errors.New("failed to reconstruct secret from shares")
)

// CalculateThreshold computes simple majority threshold k = floor(N/2) + 1 for N enrolled guardians (1..5).
func CalculateThreshold(n int) (int, error) {
	if n < 1 || n > 5 {
		return 0, ErrInvalidGuardianCount
	}
	return (n / 2) + 1, nil
}

// GenerateMasterSecret creates a 32-byte (256-bit) cryptographically random master recovery secret.
func GenerateMasterSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate random master secret: %w", err)
	}
	return secret, nil
}

// Zeroize explicitly overwrites a byte slice with zeros to wipe sensitive data from memory.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HashSecret returns the upper-case SHA-256 hex string of a byte slice.
func HashSecret(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SplitSecret splits a master secret into n shares with threshold k using HashiCorp Vault Shamir (GF(2^8)).
func SplitSecret(secret []byte, n, k int) ([][]byte, error) {
	if n < 1 || n > 5 {
		return nil, ErrInvalidGuardianCount
	}
	if k < 1 || k > n {
		return nil, fmt.Errorf("invalid threshold k=%d for n=%d", k, n)
	}

	shares, err := shamir.Split(secret, n, k)
	if err != nil {
		return nil, fmt.Errorf("shamir split error: %w", err)
	}

	return shares, nil
}

// CombineShares reconstructs the master secret from a slice of submitted shares using HashiCorp Vault Shamir.
func CombineShares(shares [][]byte, k int) ([]byte, error) {
	if len(shares) < k {
		return nil, fmt.Errorf("%w: provided %d shares, required %d", ErrInvalidShareCount, len(shares), k)
	}

	reconstructed, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReconstructionFailed, err)
	}

	return reconstructed, nil
}
