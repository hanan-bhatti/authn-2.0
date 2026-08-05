/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/validator/validator_test.go
 * Tier: Unit Testing Layer / Input Security Validation
 *
 * Description: Unit tests for security input validation, image URL verification,
 *              XSS script detection, and numeric range bounds.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package validator

import (
	"testing"
)

func TestValidateEmail(t *testing.T) {
	validEmails := []string{
		"user@example.com",
		"alex.smith@sub.domain.co.uk",
		"dev+test@authn.io",
	}

	for _, e := range validEmails {
		if err := ValidateEmail(e); err != nil {
			t.Errorf("expected valid email for '%s', got error: %v", e, err)
		}
	}

	invalidEmails := []string{
		"",
		"plainaddress",
		"@missinguser.com",
		"user@.com",
		"user@domain..com",
		"user@domain.com\x00",
		"<script>alert(1)</script>@domain.com",
	}

	for _, e := range invalidEmails {
		if err := ValidateEmail(e); err == nil {
			t.Errorf("expected error for invalid email '%s', got nil", e)
		}
	}
}

func TestValidateImageURL(t *testing.T) {
	validURLs := []struct {
		input    string
		expected string
	}{
		{"https://cdn.acme.local/avatars/user.png", "https://cdn.acme.local/avatars/user.png"},
		{"http://img.example.com/photo.jpg", "http://img.example.com/photo.jpg"},
		{"img.com/avatar.png", "https://img.com/avatar.png"},
		{"cdn.acme.org/profiles/alex.webp", "https://cdn.acme.org/profiles/alex.webp"},
	}

	for _, tc := range validURLs {
		res, err := ValidateImageURL(tc.input)
		if err != nil {
			t.Errorf("expected valid image URL for '%s', got error: %v", tc.input, err)
		}
		if res != tc.expected {
			t.Errorf("expected '%s', got '%s'", tc.expected, res)
		}
	}

	invalidURLs := []string{
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"file:///etc/passwd",
		"ftp://malicious.com/virus.exe",
		"http://<script>alert(1)</script>.com",
		"vbscript:msgbox(1)",
	}

	for _, u := range invalidURLs {
		_, err := ValidateImageURL(u)
		if err == nil {
			t.Errorf("expected error for malicious image URL '%s', got nil", u)
		}
	}
}

func TestSanitizeString(t *testing.T) {
	s, err := SanitizeString("  Alex Smith  ", 2, 50)
	if err != nil || s != "Alex Smith" {
		t.Errorf("expected 'Alex Smith', got '%s', err: %v", s, err)
	}

	_, err = SanitizeString("<script>alert(1)</script>", 1, 100)
	if err == nil {
		t.Errorf("expected XSS error for script tag, got nil")
	}

	_, err = SanitizeString("a", 3, 10)
	if err == nil {
		t.Errorf("expected min length error, got nil")
	}
}

func TestValidateIntRange(t *testing.T) {
	if err := ValidateIntRange(15, 1, 60, "duration"); err != nil {
		t.Errorf("expected 15 to be in range 1..60, got %v", err)
	}

	if err := ValidateIntRange(0, 1, 60, "duration"); err == nil {
		t.Errorf("expected error for 0 in range 1..60, got nil")
	}

	if err := ValidateIntRange(100, 1, 60, "duration"); err == nil {
		t.Errorf("expected error for 100 in range 1..60, got nil")
	}
}
