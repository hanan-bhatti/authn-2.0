/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/shamir/shamir_test.go
 * Tier: Cryptographic Primitives Package / Shamir Tests
 *
 * Description: Unit tests for GF(2^8) Galois Field arithmetic and Shamir secret splitting.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package shamir

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamir_SplitAndCombine(t *testing.T) {
	secret := []byte("super_secret_master_recovery_key_32bytes!")
	require.Len(t, secret, 41)

	// Split 3-of-5
	shares, err := Split(secret, 5, 3)
	require.NoError(t, err)
	require.Len(t, shares, 5)

	// Any 3 shares reconstruct
	reconstructed, err := Combine([][]byte{shares[0], shares[2], shares[4]})
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secret, reconstructed))

	// 2 shares fail or yield wrong secret
	reconstructedInvalid, err := Combine([][]byte{shares[0], shares[1]})
	if err == nil {
		assert.False(t, bytes.Equal(secret, reconstructedInvalid))
	}
}
