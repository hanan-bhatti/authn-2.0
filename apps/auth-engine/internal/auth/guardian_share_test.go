/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/guardian_share_test.go
 * Tier: Internal Feature Package / Guardian Consensus Tests
 *
 * Description: Unit tests for the majority threshold rule, guardian share generation, share digest
 *              storage form, and memory zeroization.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"bytes"
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

// A majority is what stops one guardian acting alone, so the rule is asserted as the property it
// exists for rather than only as a table of expected numbers.
func TestCalculateThreshold_NeverOneOnceASecondGuardianExists(t *testing.T) {
	for n := 2; n <= 5; n++ {
		k, err := CalculateThreshold(n)
		require.NoError(t, err)
		assert.Greater(t, k, 1, "n=%d must require more than one guardian", n)
		assert.LessOrEqual(t, k, n, "n=%d must be satisfiable by the enrolled guardians", n)
	}
}

func TestGenerateGuardianShare_IndependentAndFullLength(t *testing.T) {
	first, err := GenerateGuardianShare()
	require.NoError(t, err)
	require.Len(t, first, 32)

	second, err := GenerateGuardianShare()
	require.NoError(t, err)
	assert.False(t, bytes.Equal(first, second), "two guardians must not be handed the same share")

	Zeroize(first)
	Zeroize(second)
}

func TestHashSecret_IsTheStorageFormAndNotTheShare(t *testing.T) {
	share, err := GenerateGuardianShare()
	require.NoError(t, err)
	defer Zeroize(share)

	digest := HashSecret(share)
	assert.Len(t, digest, 64, "share hashes are stored as 64 hex characters of SHA-256")
	assert.NotContains(t, digest, string(share), "the digest must not carry the share")

	// Same input, same digest: a guardian submitting their saved share has to match the row.
	assert.Equal(t, digest, HashSecret(share))

	other, err := GenerateGuardianShare()
	require.NoError(t, err)
	defer Zeroize(other)
	assert.NotEqual(t, digest, HashSecret(other))
}

func TestZeroize(t *testing.T) {
	buffer := []byte("super_secret_recovery_data_12345")
	Zeroize(buffer)
	assert.Equal(t, make([]byte, len(buffer)), buffer)
}
