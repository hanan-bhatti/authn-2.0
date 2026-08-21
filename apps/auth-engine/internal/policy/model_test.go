package policy

import (
	"testing"
	"time"
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
