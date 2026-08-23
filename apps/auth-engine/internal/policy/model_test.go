package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
)

func TestValidatePassword_DefaultPolicy(t *testing.T) {
	p := DefaultPasswordPolicy() // Requires numeric, min length 8

	// Valid password (8 characters)
	missing := ValidatePassword(p, "Pass1234")
	if len(missing) != 0 {
		t.Fatalf("expected no missing criteria for valid password, got %v", missing)
	}

	// Missing numeric
	missing = ValidatePassword(p, "Password")
	if len(missing) != 1 || missing[0] != "require_numeric" {
		t.Fatalf("expected ['require_numeric'], got %v", missing)
	}

	// Too short (< 8 chars)
	missing = ValidatePassword(p, "Pass123")
	if len(missing) != 1 || missing[0] != "min_length" {
		t.Fatalf("expected ['min_length'], got %v", missing)
	}
}

// Length is a character count, not a byte count. Counting bytes made the minimum
// weaker than the policy advertised: a five-character password of astral
// characters occupies eleven bytes and satisfied a minimum of eight.
func TestValidatePassword_LengthCountsCharactersNotBytes(t *testing.T) {
	p := DefaultPasswordPolicy() // min length 8, requires a digit

	short := "AA1\U0001f600\U0001f601" // 5 characters, 11 bytes
	if len(short) < 8 {
		t.Fatalf("test is vacuous: %q is only %d bytes", short, len(short))
	}

	missing := ValidatePassword(p, short)
	if len(missing) != 1 || missing[0] != "min_length" {
		t.Fatalf("expected ['min_length'] for a 5-character password, got %v", missing)
	}
}

// A password is measured after normalization, because that is the form that gets
// hashed. Eight characters typed as decomposed sequences is eight characters.
func TestValidatePassword_LengthIsMeasuredAfterNormalization(t *testing.T) {
	p := PasswordPolicy{EnforcementMode: "require", MinLength: 8, MaxLength: 64}

	// Five vowels each followed by U+0308 COMBINING DIAERESIS, plus "123": thirteen
	// characters as typed, eight once composed. Written as escapes because a
	// decomposed literal is indistinguishable from a composed one in source.
	decomposed := "a\u0308e\u0308i\u0308o\u0308u\u0308123"

	if got := len([]rune(decomposed)); got != 13 {
		t.Fatalf("test fixture is wrong: expected 13 runes decomposed, got %d", got)
	}

	if missing := ValidatePassword(p, decomposed); len(missing) != 0 {
		t.Fatalf("expected an 8-character composed password to pass, got %v", missing)
	}
}

// Over the normalization ceiling the answer is max_length and nothing else, so
// the engine never normalizes an input it is about to refuse.
func TestValidatePassword_RefusesInputOverTheNormalizationCeiling(t *testing.T) {
	p := DefaultPasswordPolicy()

	oversized := strings.Repeat("a", crypto.MaxPasswordInputBytes+1)

	missing := ValidatePassword(p, oversized)
	if len(missing) != 1 || missing[0] != "max_length" {
		t.Fatalf("expected ['max_length'], got %v", missing)
	}
}

func TestValidatePassword_StrictPolicy(t *testing.T) {
	p := PasswordPolicy{
		EnforcementMode:  "require",
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumeric:   true,
		RequireSpecial:   true,
		MinLength:        8,
		MaxLength:        64,
	}

	// Non-compliant password: "simple" (no upper, no digit, no special, length 6 < 8)
	missing := ValidatePassword(p, "simple")
	expected := map[string]bool{
		"min_length":        true,
		"require_uppercase": true,
		"require_numeric":   true,
		"require_special":   true,
	}

	if len(missing) != 4 {
		t.Fatalf("expected 4 missing criteria, got %d: %v", len(missing), missing)
	}
	for _, m := range missing {
		if !expected[m] {
			t.Errorf("unexpected missing criterion: %s", m)
		}
	}
}

func TestValidAccessTokenTTLMinutes(t *testing.T) {
	// Zero is the "inherit the deployment default" signal and stays settable.
	for _, m := range []int{0, 15, 30, 60} {
		if !ValidAccessTokenTTLMinutes(m) {
			t.Errorf("expected %d minutes to be settable", m)
		}
	}

	// 1440 was the old ceiling and 45 reads like a reasonable middle, so both are
	// the values a caller is most likely to try. Neither is on the menu.
	for _, m := range []int{-1, 1, 14, 16, 45, 120, 1440} {
		if ValidAccessTokenTTLMinutes(m) {
			t.Errorf("expected %d minutes to be rejected", m)
		}
	}
}

func TestNormalizeSessionPolicyAccessTokenTTL(t *testing.T) {
	// A stored value off the menu snaps down to a member, never up: normalization
	// runs on the login path, where lengthening a lifetime nobody asked for is the
	// one outcome that cannot be reported to anybody.
	cases := map[int]int{
		0:    0,
		15:   15,
		30:   30,
		60:   60,
		45:   30,
		59:   30,
		61:   60,
		120:  60,
		1440: 60,
		// Below the shortest member there is nothing to snap down to.
		5:  15,
		1:  15,
		-1: 15,
	}

	for stored, want := range cases {
		got := NormalizeSessionPolicy(SessionPolicy{AccessTokenTTLMinutes: stored}).AccessTokenTTLMinutes
		if got != want {
			t.Errorf("stored %d minutes: expected %d, got %d", stored, want, got)
		}
	}
}

func TestSessionPolicyAccessTokenTTLResolution(t *testing.T) {
	fallback := 15 * time.Minute

	if got := (SessionPolicy{AccessTokenTTLMinutes: 0}).AccessTokenTTL(fallback); got != fallback {
		t.Errorf("zero minutes should inherit the fallback, got %v", got)
	}
	if got := (SessionPolicy{AccessTokenTTLMinutes: 60}).AccessTokenTTL(fallback); got != time.Hour {
		t.Errorf("60 minutes should resolve to an hour, got %v", got)
	}
}
