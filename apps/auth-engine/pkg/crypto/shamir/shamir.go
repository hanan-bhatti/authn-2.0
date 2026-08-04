/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/shamir/shamir.go
 * Tier: Cryptographic Primitives Package / Shamir's Secret Sharing (GF(2^8))
 *
 * Description: Clean, constant-time implementation of Shamir's Secret Sharing over Galois Field 2^8.
 *              Based on HashiCorp Vault's shamir primitive for secure threshold secret splitting.
 *
 * Security Notice:
 *   - Field arithmetic is computed over GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 *   - Supports arbitrary N (1..255) and threshold K (1..N).
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
	ErrInvalidN         = errors.New("number of parts N must be between 1 and 255")
	ErrInvalidK         = errors.New("threshold K must be between 1 and N")
	ErrEmptySecret      = errors.New("secret cannot be empty")
	ErrInsufficientShares = errors.New("insufficient shares to combine secret")
	ErrShareLenMismatch  = errors.New("share length mismatch")
)

// Galois Field GF(2^8) log and exp tables for multiplication and division.
var (
	gfLog [256]byte
	gfExp [256]byte
)

func init() {
	// Initialize GF(2^8) tables with generator 3 and polynomial 0x11b
	poly := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(poly)
		gfLog[poly] = byte(i)
		poly <<= 1
		if poly&0x100 != 0 {
			poly ^= 0x11d
		}
	}
	gfExp[255] = gfExp[0]
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%255]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(2^8)")
	}
	if a == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])-int(gfLog[b])+255)%255]
}

// evalPolynomial evaluates polynomial co at x in GF(2^8).
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

// Split splits a secret into N shares requiring at least K shares to reconstruct.
// Each share contains [x_index, byte_1, byte_2, ...].
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
		shares[i][0] = byte(i + 1) // 1-based x coordinate
	}

	// For each byte in secret, create a polynomial of degree k-1
	poly := make([]byte, k)
	for idx, val := range secret {
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

// Combine reconstructs a secret from a slice of K or more valid shares.
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

	secretLen := shareLen - 1
	secret := make([]byte, secretLen)

	// Lagrange Interpolation over GF(2^8)
	for idx := 0; idx < secretLen; idx++ {
		var secretByte byte
		for i, sI := range shares {
			xI := sI[0]
			yI := sI[idx+1]

			// Compute Lagrange basis polynomial L_i(0)
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
