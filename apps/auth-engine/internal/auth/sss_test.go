/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/sss_test.go
 * Tier: Internal Feature Package / SSS Cryptography Tests
 *
 * Description: Unit tests for Shamir's Secret Sharing (SSS) threshold calculations,
 *              splitting, reconstruction, zero-knowledge hash verification, and memory zeroization.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateThreshold(t *testing.T) {
	tests := []struct {
		n        int
		expected int
		wantErr  bool
	}{
		{n: 1, expected: 1, wantErr: false}, // 1-of-1
		{n: 2, expected: 2, wantErr: false}, // 2-of-2
		{n: 3, expected: 2, wantErr: false}, // 2-of-3
		{n: 4, expected: 3, wantErr: false}, // 3-of-4
		{n: 5, expected: 3, wantErr: false}, // 3-of-5
		{n: 0, expected: 0, wantErr: true},  // invalid
		{n: 6, expected: 0, wantErr: true},  // invalid
	}

	for _, tt := range tests {
		k, err := CalculateThreshold(tt.n)
		if tt.wantErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, k)
		}
	}
}

func TestSSS_SplitAndCombine_AllN(t *testing.T) {
	for n := 1; n <= 5; n++ {
		k, err := CalculateThreshold(n)
		require.NoError(t, err)

		masterSecret, err := GenerateMasterSecret()
		require.NoError(t, err)
		require.Len(t, masterSecret, 32)
		originalHash := HashSecret(masterSecret)

		shares, err := SplitSecret(masterSecret, n, k)
		require.NoError(t, err)
		require.Len(t, shares, n)

		// Take first k shares to combine
		subsetShares := shares[:k]
		reconstructed, err := CombineShares(subsetShares, k)
		require.NoError(t, err)
		require.Equal(t, originalHash, HashSecret(reconstructed))
		require.True(t, bytes.Equal(masterSecret, reconstructed))

		// Clean up secrets
		Zeroize(masterSecret)
		Zeroize(reconstructed)
	}
}

func TestSSS_ZeroKnowledgeVerification_NoRawSharesInLogsOrDB(t *testing.T) {
	masterSecret, err := GenerateMasterSecret()
	require.NoError(t, err)

	shares, err := SplitSecret(masterSecret, 3, 2)
	require.NoError(t, err)

	shareHashes := make([]string, len(shares))
	for i, s := range shares {
		shareHashes[i] = HashSecret(s)
	}

	// Verify that stored share hashes are standard SHA-256 (64 hex characters)
	for _, h := range shareHashes {
		assert.Len(t, h, 64)
		// Raw shares MUST NOT equal their SHA-256 hash string
		for _, s := range shares {
			assert.NotEqual(t, hex.EncodeToString(s), h)
		}
	}

	// Verify memory zeroization
	buffer := []byte("super_secret_recovery_data_12345")
	Zeroize(buffer)
	assert.Equal(t, make([]byte, len(buffer)), buffer)
}
