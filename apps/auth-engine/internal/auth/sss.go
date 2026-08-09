/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/sss.go
 * Tier: Internal Feature Package / Cryptographic SSS Service
 *
 * Description: Guardian-scale wrapper over the pkg/crypto/shamir primitive. Fixes the threshold rule
 *              at a simple majority of the enrolled guardians, caps the roster at five, generates and
 *              splits the 256-bit master recovery secret, and supplies the digest and zeroization
 *              helpers callers use to verify a reconstruction and to clear share material afterwards.
 *
 * Security Notice:
 *   - Nothing here retains a secret or a share: buffers are owned by the caller, which must Zeroize
 *     them once used.
 *   - Only SHA-256 digests of shares and secrets are persisted; a share itself never reaches storage.
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
	// ErrInvalidGuardianCount reports a roster size outside the supported 1..5 range. The ceiling is
	// this package's own: the underlying primitive supports up to 255 parts.
	ErrInvalidGuardianCount = errors.New("guardian count N must be between 1 and 5")

	// ErrInvalidShareCount reports that fewer than k shares were offered for reconstruction. It is
	// the only threshold check in the combine path, since the primitive itself cannot tell a
	// sufficient share set from an insufficient one.
	ErrInvalidShareCount = errors.New("insufficient shares to meet threshold k")

	// ErrReconstructionFailed wraps a structural failure inside the primitive — an empty share set,
	// or shares of differing lengths. It does not signal a wrong secret, which reconstructs silently.
	ErrReconstructionFailed = errors.New("failed to reconstruct secret from shares")
)

// CalculateThreshold returns the number of shares k required to reconstruct a secret split across n
// enrolled guardians: a simple majority, floor(n/2)+1. That yields 1-of-1, 2-of-2, 2-of-3, 3-of-4,
// and 3-of-5, so no single guardian can ever recover an account alone once a second is enrolled,
// while one unavailable guardian never strands a roster of three or more.
//
// It returns ErrInvalidGuardianCount for n outside 1..5, which means the caller's roster has drifted
// past the supported range and no threshold can be quoted for it.
func CalculateThreshold(n int) (int, error) {
	if n < 1 || n > 5 {
		return 0, ErrInvalidGuardianCount
	}
	return (n / 2) + 1, nil
}

// GenerateMasterSecret returns 32 bytes (256 bits) read from the operating system CSPRNG, to be used
// as the master recovery secret that gets split across guardians. An error means the system entropy
// source is unavailable; the caller must abort rather than fall back to a weaker source, since this
// value is the sole secret protecting the account recovery path.
func GenerateMasterSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate random master secret: %w", err)
	}
	return secret, nil
}

// Zeroize overwrites b in place with zero bytes. It clears exactly this buffer: any copy the caller
// made, any string the bytes were converted into, and any slice the runtime relocated during a heap
// move remain untouched, so secrets must be handled in one buffer from creation to wipe.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HashSecret returns the SHA-256 digest of data as lower-case hex. It is the storage form for both
// guardian share hashes and master secret digests, and the comparison form used to confirm that a
// reconstruction produced the original secret.
func HashSecret(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SplitSecret splits secret into n Shamir shares of which any k reconstruct it, and returns them
// ordered by x coordinate — shares[i] carries coordinate i+1.
//
// Sharing is byte-wise over GF(2^8): each byte of the secret gets its own independent degree-(k-1)
// polynomial with random coefficients, so share length tracks secret length rather than expanding
// it. Each returned share is len(secret)+1 bytes — a leading 1-based x coordinate followed by one
// evaluation byte per secret byte — which makes a 32-byte master secret produce 33-byte shares.
// The coordinate is part of the share: strip it and the share is unusable.
//
// The returned buffers hold real share material. The caller owns them and must Zeroize them once
// their digests are stored.
//
// It returns ErrInvalidGuardianCount for n outside 1..5, a plain error for k outside 1..n, and a
// wrapped error when the primitive rejects the secret (an empty one) or the CSPRNG fails to supply
// polynomial coefficients — in which case no usable share set exists and enrollment must not proceed.
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

// CombineShares reconstructs a secret by Lagrange interpolation at x=0 over GF(2^8), using every
// share passed in. Shares may arrive in any order, since each carries its own x coordinate, and
// supplying more than k of them is harmless.
//
// k is used only to reject a set that is too small up front. Interpolation over a share set that is
// insufficient, or that mixes shares from different splits, produces a wrong secret rather than an
// error — the mathematics has no notion of a failed reconstruction. The caller must therefore
// confirm the result, by comparing HashSecret of the output against the stored digest of the
// original secret, before treating it as recovered.
//
// It returns ErrInvalidShareCount when fewer than k shares were supplied, and ErrReconstructionFailed
// when the share set is structurally invalid, meaning empty, malformed, or of inconsistent length.
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
