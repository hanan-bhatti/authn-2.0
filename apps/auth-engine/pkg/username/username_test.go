/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/username/username_test.go
 * Tier: Shared Package / Identifier Normalization
 *
 * Every non-ASCII fixture in this file is written as a \u escape rather than as a
 * literal character. A composed literal is indistinguishable from its decomposed
 * form by eye, and an editor or formatter that normalises on save would rewrite
 * the fixture into ASCII and leave a test that asserts nothing while still
 * passing. TestFixturesAreNotAscii fails if that happens anyway.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package username

import (
	"errors"
	"strings"
	"testing"
	"unicode"
)

// Fixtures whose whole purpose is to be non-ASCII, named so the self-check below
// can assert that property without restating each literal.
const (
	// U+FF41 U+FF4C U+FF45 U+FF58 fullwidth latin small letters, folding to "alex".
	fullwidthAlex = "\uff41\uff4c\uff45\uff58"
	// U+2162 roman numeral three, folding to "III" and then lower-casing to "iii".
	romanNumeral = "al\u2162"
	// U+0430 cyrillic small letter a, rendered identically to latin "a".
	cyrillicLeading = "\u0430lex"
	// U+0435 cyrillic small letter ie, rendered identically to latin "e".
	cyrillicMiddle = "al\u0435x"
	// U+03BF greek small letter omicron, rendered identically to latin "o".
	greekOmicron = "al\u03bfx"
	// U+13AA cherokee letter a, rendered as an upper-case latin "A".
	cherokeeLeading = "\u13aalex"
	// U+200D zero width joiner, which renders as nothing at all.
	zeroWidthJoiner = "ale\u200dx"
	// U+202E right-to-left override, which reverses everything rendered after it.
	bidiOverride = "alex\u202e"
	// U+FDFA arabic ligature, expanding to eighteen characters under NFKC.
	arabicLigature = "\ufdfa"
)

// TestFixturesAreNotAscii guards the fixtures themselves. If a tool rewrote any
// of them to plain ASCII, the confusable tests below would pass for the wrong
// reason and report a protection that is no longer there.
func TestFixturesAreNotAscii(t *testing.T) {
	fixtures := map[string]string{
		"fullwidthAlex":   fullwidthAlex,
		"romanNumeral":    romanNumeral,
		"cyrillicLeading": cyrillicLeading,
		"cyrillicMiddle":  cyrillicMiddle,
		"greekOmicron":    greekOmicron,
		"cherokeeLeading": cherokeeLeading,
		"zeroWidthJoiner": zeroWidthJoiner,
		"bidiOverride":    bidiOverride,
		"arabicLigature":  arabicLigature,
	}

	for name, value := range fixtures {
		hasNonASCII := false
		for _, r := range value {
			if r > unicode.MaxASCII {
				hasNonASCII = true
				break
			}
		}
		if !hasNonASCII {
			t.Fatalf("fixture %s is pure ASCII (%q); the case it covers is no longer tested", name, value)
		}
	}
}

// TestCanonicalFoldsCaseAndCompatibility checks the two folds that decide whether
// two handles are one. Every pair here renders identically or nearly so on
// screen, which is the whole reason they must not be separately allocatable.
func TestCanonicalFoldsCaseAndCompatibility(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"upper case", "AlexSmith", "alexsmith"},
		{"mixed case", "aLeXsMiTh", "alexsmith"},
		{"surrounding space", "   alexsmith  ", "alexsmith"},
		{"fullwidth latin", fullwidthAlex, "alex"},
		{"compatibility ligature", romanNumeral, "aliii"},
		{"digits and underscore", "Alex_Smith_99", "alex_smith_99"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonical(tc.in)
			if err != nil {
				t.Fatalf("Canonical(%q) returned %v, want no error", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Canonical(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCanonicalIsIdempotent checks that feeding a canonical value back through
// yields the same value. Any lookup path may canonicalise more than once —
// validation at the handler and again at the repository — and a form that shifted
// on a second pass would make a stored handle unfindable.
func TestCanonicalIsIdempotent(t *testing.T) {
	for _, in := range []string{"AlexSmith", fullwidthAlex, "a_b_c9"} {
		once, err := Canonical(in)
		if err != nil {
			t.Fatalf("Canonical(%q): %v", in, err)
		}
		twice, err := Canonical(once)
		if err != nil {
			t.Fatalf("Canonical(%q): %v", once, err)
		}
		if once != twice {
			t.Fatalf("Canonical is not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}

// TestCanonicalRefusesConfusables is the security case for the ASCII-only
// charset. Each input renders as "alex" or close to it while being a different
// code point sequence, so accepting any of them would let one account
// impersonate another with no visible difference.
func TestCanonicalRefusesConfusables(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"cyrillic a for latin a", cyrillicLeading},
		{"cyrillic ie for latin e", cyrillicMiddle},
		{"greek omicron for latin o", greekOmicron},
		{"cherokee a for latin a", cherokeeLeading},
		{"zero width joiner", zeroWidthJoiner},
		{"right to left override", bidiOverride},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonical(tc.in)
			if err == nil {
				t.Fatalf("Canonical(%q) = %q, want a refusal", tc.in, got)
			}
			if !errors.Is(err, ErrCharset) {
				t.Fatalf("Canonical(%q) returned %v, want ErrCharset", tc.in, err)
			}
		})
	}
}

// TestCanonicalEnforcesShape covers each structural rule and the error it
// reports, because the availability endpoint renders the specific reason and a
// rule that collapsed into a generic failure would leave the user guessing.
func TestCanonicalEnforcesShape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrEmpty},
		{"whitespace only", "   ", ErrEmpty},
		{"two characters", "al", ErrTooShort},
		{"thirty one characters", strings.Repeat("a", MaxLength+1), ErrTooLong},
		{"leading digit", "1alex", ErrLeadingChar},
		{"leading underscore", "_alex", ErrLeadingChar},
		{"trailing underscore", "alex_", ErrTrailingChar},
		{"embedded space", "alex smith", ErrCharset},
		{"hyphen", "alex-smith", ErrCharset},
		{"at sign", "@alex", ErrCharset},
		{"dot", "alex.smith", ErrCharset},
		{"emoji", "alex\U0001f600", ErrCharset},
		{"reserved", "admin", ErrReservedHandle},
		{"reserved after folding", "ADMIN", ErrReservedHandle},
		{"reserved route", "settings", ErrReservedHandle},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Canonical(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Canonical(%q) returned %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

// TestCanonicalAcceptsBoundaryLengths checks both ends of the length range
// inclusively, since an off-by-one at either bound silently narrows the
// namespace.
func TestCanonicalAcceptsBoundaryLengths(t *testing.T) {
	for _, in := range []string{strings.Repeat("a", MinLength), strings.Repeat("a", MaxLength)} {
		if _, err := Canonical(in); err != nil {
			t.Fatalf("Canonical(%d characters): %v", len(in), err)
		}
	}
}

// TestCanonicalBoundsInput checks the work bound. NFKC can expand its input, so
// an oversized value must be refused before it is normalised rather than after.
func TestCanonicalBoundsInput(t *testing.T) {
	oversized := strings.Repeat(arabicLigature, 200)
	if len(oversized) <= MaxInputBytes {
		t.Fatalf("fixture is %d bytes, which is inside the %d-byte bound it exists to exceed",
			len(oversized), MaxInputBytes)
	}
	if _, err := Canonical(oversized); !errors.Is(err, ErrTooLong) {
		t.Fatalf("an expanding input above the byte bound returned %v, want ErrTooLong", err)
	}
}
