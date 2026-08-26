/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/guardian_share.go
 * Tier: Internal Feature Package / Guardian Consensus Primitives
 *
 * Description: The primitives behind M-of-N guardian recovery: the threshold rule fixed at a simple
 *              majority of the enrolled guardians, generation of one guardian's 256-bit share, and
 *              the digest and zeroization helpers used to store and compare one.
 *
 * Security Notice:
 *   - Nothing here retains a secret: buffers are owned by the caller, which must Zeroize them once
 *     their digest has been taken.
 *   - Only SHA-256 digests of shares reach storage. A share itself exists in the engine for the one
 *     request that mints it and is not recoverable afterwards.
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
)

// ErrInvalidGuardianCount reports a roster size outside the supported 1..5 range, meaning the
// caller's guardian list has drifted past what the threshold rule covers and no threshold can be
// quoted for it.
var ErrInvalidGuardianCount = errors.New("guardian count N must be between 1 and 5")

// CalculateThreshold returns the number of guardians k who must approve a recovery when n are
// enrolled: a simple majority, floor(n/2)+1. That yields 1-of-1, 2-of-2, 2-of-3, 3-of-4 and 3-of-5,
// so no single guardian can ever recover an account alone once a second is enrolled, while one
// unavailable guardian never strands a roster of three or more.
//
// The threshold is derived on demand rather than stored, so it always describes the roster as it
// stands: removing a guardian lowers the bar immediately, with no stored copy left to go stale.
func CalculateThreshold(n int) (int, error) {
	if n < 1 || n > 5 {
		return 0, ErrInvalidGuardianCount
	}
	return (n / 2) + 1, nil
}

// GenerateGuardianShare returns 32 bytes (256 bits) read from the operating system CSPRNG, to be
// handed to one guardian as their half of the recovery proof.
//
// Each guardian's share is independent — not a point on a polynomial shared with the others — so one
// share reveals nothing about any other, and re-issuing one leaves the rest untouched.
//
// An error means the system entropy source is unavailable; the caller must abort rather than fall
// back to a weaker source, since this value is the sole secret standing behind that guardian's
// approval.
func GenerateGuardianShare() ([]byte, error) {
	share := make([]byte, 32)
	if _, err := rand.Read(share); err != nil {
		return nil, fmt.Errorf("failed to generate random guardian share: %w", err)
	}
	return share, nil
}

// Zeroize overwrites b in place with zero bytes. It clears exactly this buffer: any copy the caller
// made, any string the bytes were converted into, and any slice the runtime relocated during a heap
// move remain untouched, so secrets must be handled in one buffer from creation to wipe.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HashSecret returns the SHA-256 digest of data as lower-case hex. It is the storage form for
// guardian share hashes and for invitation tokens, and the comparison form used to confirm that a
// submitted share belongs to an enrolled guardian.
func HashSecret(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
