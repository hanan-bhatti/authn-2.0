/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/shamir/shamir.go
 * Tier: Shared Package / Threshold Secret Sharing
 *
 * Shamir's Secret Sharing over GF(2^8), used to split an account-recovery
 * master secret among guardians so that no single guardian can recover it
 * alone.
 *
 * The scheme is information-theoretic, not computational: with fewer than the
 * threshold number of shares, every possible secret remains exactly as likely
 * as it was before. Holding k-1 shares is no better than holding none, and no
 * amount of computing power changes that.
 *
 * Each byte of the secret is shared independently. A random polynomial of
 * degree k-1 is drawn with the secret byte as its constant term, and share i
 * receives that polynomial evaluated at x = i. Recovering the secret means
 * interpolating those points back to x = 0, which needs k of them; k-1 points
 * leave the constant term completely undetermined.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors / HashiCorp Vault License
 */

package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
)

var (
	// ErrInvalidN means the requested share count is outside 1..255. The field
	// has only 255 non-zero elements, so there are only 255 usable x
	// coordinates.
	ErrInvalidN = errors.New("number of parts N must be between 1 and 255")
	// ErrInvalidK means the threshold is not in 1..N. A threshold above N would
	// produce shares that can never be combined.
	ErrInvalidK = errors.New("threshold K must be between 1 and N")
	// ErrEmptySecret means there was nothing to split.
	ErrEmptySecret = errors.New("secret cannot be empty")
	// ErrInsufficientShares means Combine was given no shares at all.
	ErrInsufficientShares = errors.New("insufficient shares to combine secret")
	// ErrShareLenMismatch means the supplied shares are of differing lengths and
	// therefore cannot come from the same split.
	ErrShareLenMismatch = errors.New("share length mismatch")
	// ErrInvalidShareX means a share carries an unusable x coordinate: either
	// zero, which is reserved for the secret itself, or one that duplicates
	// another share's. Interpolation is undefined for both.
	ErrInvalidShareX = errors.New("invalid share: x coordinates must be non-zero and distinct")
)

// Logarithm and exponentiation tables for GF(2^8), which turn field
// multiplication and division into table lookups and integer addition.
//
// The field is built modulo the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
// (0x11d) with 2 as the primitive element. The choice matters: 2 generates all
// 255 non-zero elements under 0x11d, whereas under the AES polynomial 0x11b it
// has order 51 and would cycle through only a fifth of the field, collapsing
// the tables.
var (
	gfLog [256]byte
	gfExp [256]byte
)

func init() {
	// Walk the powers of the generator. Shifting left multiplies by x; when
	// that overflows 8 bits, reducing by the polynomial brings it back into
	// the field.
	poly := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(poly)
		gfLog[poly] = byte(i)
		poly <<= 1
		if poly&0x100 != 0 {
			poly ^= 0x11d
		}
	}

	// The exponent cycle has period 255, so index 255 wraps to the same value
	// as index 0. Storing it lets gfMul add two logs, each at most 254, and
	// index the table without a separate bounds check.
	gfExp[255] = gfExp[0]

	// gfLog[0] is deliberately left zero: the logarithm of zero is undefined.
	// gfMul and gfDiv special-case a zero operand before consulting the table.
}

// gfAdd adds two field elements. In characteristic 2 addition and subtraction
// are both XOR, which is why subtraction never appears in this file.
func gfAdd(a, b byte) byte {
	return a ^ b
}

// gfMul multiplies two field elements via their logarithms.
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%255]
}

// gfDiv divides a by b.
//
// It panics on a zero divisor. Callers must rule that out first; Combine does
// so by rejecting duplicate x coordinates, which are the only way a zero
// denominator can arise during interpolation.
func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(2^8)")
	}
	if a == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])-int(gfLog[b])+255)%255]
}

// evalPolynomial evaluates the polynomial with coefficients co at x, using
// Horner's method so the cost is one multiply and one add per coefficient.
func evalPolynomial(co []byte, x byte) byte {
	if x == 0 {
		return co[0]
	}
	out := co[len(co)-1]
	for i := len(co) - 2; i >= 0; i-- {
		out = gfAdd(co[i], gfMul(out, x))
	}
	return out
}

// Split divides secret into n shares, any k of which reconstruct it.
//
// Each share is its x coordinate followed by one evaluated byte per secret
// byte, so a share is len(secret)+1 bytes long. Shares are self-identifying and
// may be presented to Combine in any order.
//
// Returns ErrEmptySecret, ErrInvalidN or ErrInvalidK for unusable parameters,
// or an error if the system random source fails. A random failure is fatal
// rather than retryable: predictable coefficients would let a single share
// reveal the secret, defeating the entire scheme.
func Split(secret []byte, n, k int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if n < 1 || n > 255 {
		return nil, ErrInvalidN
	}
	if k < 1 || k > n {
		return nil, ErrInvalidK
	}

	shares := make([][]byte, n)
	for i := 0; i < n; i++ {
		shares[i] = make([]byte, len(secret)+1)
		// x coordinates start at 1. Zero is where the secret itself lives, so
		// handing it out as a share would hand out the secret.
		shares[i][0] = byte(i + 1)
	}

	poly := make([]byte, k)
	for idx, val := range secret {
		// A fresh polynomial per secret byte: the constant term is the byte,
		// the remaining k-1 coefficients are random. Reusing coefficients
		// across bytes would correlate the shares and leak structure.
		poly[0] = val
		if k > 1 {
			if _, err := rand.Read(poly[1:]); err != nil {
				return nil, fmt.Errorf("failed to generate random polynomial coefficients: %w", err)
			}
		}

		for i := 0; i < n; i++ {
			x := byte(i + 1)
			shares[i][idx+1] = evalPolynomial(poly, x)
		}
	}

	return shares, nil
}

// Combine reconstructs a secret from shares produced by Split.
//
// Returns ErrInsufficientShares when given none, ErrShareLenMismatch when the
// shares are not all the same length, and ErrInvalidShareX when a share's x
// coordinate is zero or repeats another's.
//
// It cannot report whether enough shares were supplied. Interpolating fewer
// than the threshold yields a different polynomial, so the result is a
// well-formed byte string of the right length that simply is not the secret,
// and it is returned with a nil error. Callers must verify the reconstructed
// value out of band — comparing it against a stored digest, for example — and
// must not treat a successful return as proof of recovery.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, ErrInsufficientShares
	}

	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, errors.New("invalid share payload format")
	}

	for _, s := range shares {
		if len(s) != shareLen {
			return nil, ErrShareLenMismatch
		}
	}

	// Reject unusable x coordinates before interpolating. Two shares sharing an
	// x make the Lagrange denominator zero, and shares reach this function from
	// user-submitted recovery input, so this must be an error and not a panic.
	seenX := make(map[byte]bool, len(shares))
	for _, s := range shares {
		x := s[0]
		if x == 0 || seenX[x] {
			return nil, ErrInvalidShareX
		}
		seenX[x] = true
	}

	secretLen := shareLen - 1
	secret := make([]byte, secretLen)

	// Lagrange interpolation evaluated at x = 0, one secret byte at a time.
	for idx := 0; idx < secretLen; idx++ {
		var secretByte byte
		for i, sI := range shares {
			xI := sI[0]
			yI := sI[idx+1]

			// Basis polynomial L_i(0) = product over j != i of x_j / (x_i - x_j).
			// Subtraction is XOR here, so the denominator term is gfAdd.
			num := byte(1)
			den := byte(1)

			for j, sJ := range shares {
				if i == j {
					continue
				}
				xJ := sJ[0]
				num = gfMul(num, xJ)
				den = gfMul(den, gfAdd(xI, xJ))
			}

			lagrange := gfDiv(num, den)
			secretByte = gfAdd(secretByte, gfMul(yI, lagrange))
		}
		secret[idx] = secretByte
	}

	return secret, nil
}
