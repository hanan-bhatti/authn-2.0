/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/argon2.go
 * Tier: Shared Package / Password Hashing
 *
 * Argon2id password hashing and verification, at the cost parameters RFC 9106
 * recommends for a general-purpose server.
 *
 * Argon2id is the hybrid variant: it starts data-independent, so the early
 * passes leak nothing through the memory access pattern, then finishes
 * data-dependent, which is what makes time-memory trade-off attacks expensive.
 * That mix is why RFC 9106 names it the default choice over Argon2i or Argon2d.
 *
 * The cost is deliberate. Verifying one password takes roughly 100-200ms of CPU
 * and 64 MiB of memory here; an attacker guessing offline pays the same per
 * guess, and the memory term is what denies them the GPU and ASIC parallelism
 * that makes SHA-family hashes cheap to attack in bulk.
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

// RFC 9106 second recommended parameter set, sized for a server that verifies
// passwords on the request path.
//
// These values are a stored-hash compatibility contract, not a tuning knob:
// verification recomputes the digest with exactly these numbers, so raising any
// of them invalidates every password already in the database. Changing them
// requires a rehash-on-next-login migration that reads the cost parameters back
// out of the encoded hash.
const (
	// argon2Time is the number of passes over the memory block.
	argon2Time uint32 = 3
	// argon2MemoryKiB is the memory filled per hash, in KiB (64 MiB). This is
	// the parameter that actually resists custom hardware: an attacker needs
	// this much memory per guess in flight, not merely per guess.
	argon2MemoryKiB uint32 = 64 * 1024
	// argon2Threads is the number of parallel lanes used to fill that memory.
	argon2Threads uint8 = 4
	// argon2KeyLen is the digest length in bytes.
	argon2KeyLen uint32 = 32
	// argon2SaltLen is the per-password salt length in bytes. The salt is
	// public and stored beside the hash; its job is to make two users with the
	// same password hash differently, which defeats precomputed tables and
	// stops one cracked hash from revealing every account sharing that password.
	argon2SaltLen = 16
)

// DummyArgon2idHash is a well-formed hash of no particular password, verified
// against when the supplied email matches no user.
//
// Login must burn the same CPU whether or not the account exists. Returning
// early on "user not found" would answer in microseconds while a real account
// takes the full Argon2 computation, and that difference is measurable over the
// network — it turns the login endpoint into an account enumeration oracle.
// Its salt and digest are all zeroes but correctly sized, so verification runs
// the full computation and then fails.
const DummyArgon2idHash = "$argon2id$v=19$m=65536,t=3,p=4$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"

// HashPasswordArgon2id derives an Argon2id hash of password under a freshly
// generated random salt.
//
// The password is NFKC-normalized first — see normalize.go. Normalizing here
// rather than at the caller is what keeps the guarantee: this function and
// VerifyPasswordArgon2id are the only two doors, so a stored digest is always
// of the normalized form. Threading it through every handler that sets a
// password instead would mean one missed call site silently creates an account
// whose password only matches from the keyboard that typed it.
//
// The result is self-describing and safe to store as-is:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<hex salt>$<hex digest>
//
// Returns an error only when the system random source fails, which means the
// kernel CSPRNG is unavailable. There is no safe fallback for that: hashing a
// password under a predictable salt is worse than refusing, so the caller must
// treat it as fatal rather than retry.
func HashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed generating random salt: %w", err)
	}

	hash := argon2.IDKey([]byte(NormalizePassword(password)), salt, argon2Time, argon2MemoryKiB, argon2Threads, argon2KeyLen)

	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2MemoryKiB, argon2Time, argon2Threads,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPasswordArgon2id reports whether password produces encodedHash.
//
// The password is NFKC-normalized on the same terms as HashPasswordArgon2id, so
// a password typed as a decomposed sequence still matches a digest stored from
// the composed one. Normalization runs before the hash is even parsed, which
// keeps it on both the real and the DummyArgon2idHash path and leaves the
// constant-work property below intact.
//
// It returns false rather than an error for every failure — wrong password,
// malformed hash, unparseable hex — because the caller's response is identical
// in all of those cases and a distinguishable error would tell an attacker
// which stored hashes are corrupt.
//
// The digest comparison is constant-time. A byte-by-byte comparison that
// returns on first mismatch leaks how many leading bytes were correct, which
// is enough to reconstruct a valid digest one byte at a time.
//
// The cost parameters encoded in the hash are descriptive, not authoritative:
// verification always recomputes at the compiled-in cost. Trusting the encoded
// values would let anyone who can write to the user table downgrade a hash to
// t=1,m=8 and make it trivially crackable.
func VerifyPasswordArgon2id(password string, encodedHash string) bool {
	normalized := NormalizePassword(password)

	// Splitting the leading "$" yields an empty first element, so a well-formed
	// hash has six parts: "", "argon2id", "v=19", cost, salt, digest.
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

	hash := argon2.IDKey([]byte(normalized), salt, argon2Time, argon2MemoryKiB, argon2Threads, argon2KeyLen)
	return subtle.ConstantTimeCompare(hash, targetHash) == 1
}
