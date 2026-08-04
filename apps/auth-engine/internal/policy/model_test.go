package policy

import (
	"testing"
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
