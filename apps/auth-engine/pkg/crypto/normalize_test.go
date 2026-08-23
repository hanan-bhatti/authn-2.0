/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/normalize_test.go
 * Tier: Shared Package / Password Hashing
 *
 * Spellings are written as explicit escapes throughout. A composed and a
 * decomposed "ö" are indistinguishable in a source file, so a literal would make
 * these tests silently vacuous.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package crypto

import (
	"strings"
	"testing"
)

const (
	// "Passwörd1" with a precomposed U+00F6.
	composedPassword = "Passwörd1"
	// The same word with "o" followed by U+0308 COMBINING DIAERESIS.
	decomposedPassword = "Passwörd1"
)

func TestNormalizePassword(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "ascii is unchanged",
			input: "correct horse battery staple",
			want:  "correct horse battery staple",
		},
		{
			name:  "combining diaeresis composes onto its base",
			input: decomposedPassword,
			want:  composedPassword,
		},
		{
			name:  "already composed is left alone",
			input: composedPassword,
			want:  composedPassword,
		},
		{
			name:  "fullwidth folds to ascii",
			input: "Ｐａｓｓ",
			want:  "Pass",
		},
		{
			name:  "recovery code charset is untouched",
			input: "A1B2C3D4E5F6G7H8",
			want:  "A1B2C3D4E5F6G7H8",
		},
		{
			name:  "astral characters survive",
			input: "AA1\U0001f600\U0001f601",
			want:  "AA1\U0001f600\U0001f601",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizePassword(tc.input); got != tc.want {
				t.Fatalf("NormalizePassword(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// Input past the ceiling is handed back untouched rather than normalized, so the
// length check can refuse it without the engine having paid for an expansion.
// The repeated unit is decomposed, so normalization would shorten it and the
// comparison below would fail if the guard were missing.
func TestNormalizePasswordLeavesOversizedInputAlone(t *testing.T) {
	oversized := strings.Repeat("ö", MaxPasswordInputBytes)

	if got := NormalizePassword(oversized); got != oversized {
		t.Fatalf("oversized input was normalized: got %d bytes, want the original %d", len(got), len(oversized))
	}
}

// The reason normalization lives inside the hasher: a password stored from one
// spelling has to verify against the other, because the two are the same
// keystrokes on different platforms and look identical on screen.
func TestVerifyPasswordArgon2idMatchesAcrossSpellings(t *testing.T) {
	if composedPassword == decomposedPassword {
		t.Fatal("test is vacuous: the two spellings are byte-identical")
	}

	hash, err := HashPasswordArgon2id(composedPassword)
	if err != nil {
		t.Fatalf("hashing the composed spelling: %v", err)
	}

	if !VerifyPasswordArgon2id(decomposedPassword, hash) {
		t.Error("decomposed spelling did not verify against a digest stored from the composed one")
	}

	if !VerifyPasswordArgon2id(composedPassword, hash) {
		t.Error("composed spelling did not verify against its own digest")
	}

	if VerifyPasswordArgon2id("Password1", hash) {
		t.Error("an unrelated password verified")
	}
}

// Normalization must not make two different passwords collide, which would turn
// a usability fix into an authentication bypass. NFKC composes marks; it does not
// strip them.
func TestVerifyPasswordArgon2idStillSeparatesDistinctPasswords(t *testing.T) {
	hash, err := HashPasswordArgon2id("éclair-42")
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	if VerifyPasswordArgon2id("eclair-42", hash) {
		t.Error("dropping the accent verified; NFKC must compose marks, not strip them")
	}
}
