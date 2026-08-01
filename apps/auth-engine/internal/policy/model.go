/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/model.go
 * Tier: Domain Model Layer
 *
 * Description: Password policy definitions and default configurations.
 *              Supports Firebase-style policy options including enforcement mode,
 *              character set requirements, and force upgrade flags.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"unicode"
)

// PasswordPolicy defines tenant-level password complexity requirements.
type PasswordPolicy struct {
	EnforcementMode      string `json:"enforcement_mode"`       // "require" (default) | "notify"
	RequireUppercase     bool   `json:"require_uppercase"`      // Must contain A-Z
	RequireLowercase     bool   `json:"require_lowercase"`      // Must contain a-z
	RequireNumeric       bool   `json:"require_numeric"`        // Must contain 0-9
	RequireSpecial       bool   `json:"require_special"`        // Must contain special symbols
	ForceUpgradeOnSignin bool   `json:"force_upgrade_on_signin"` // Require upgrade on signin if non-compliant
	MinLength            int    `json:"min_length"`             // Minimum character length (default: 6)
	MaxLength            int    `json:"max_length"`             // Maximum character length (default: 4096)
}

// DefaultPasswordPolicy returns standard initial password policy settings.
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		EnforcementMode:      "require",
		RequireUppercase:     false,
		RequireLowercase:     false,
		RequireNumeric:       true,
		RequireSpecial:       false,
		ForceUpgradeOnSignin: false,
		MinLength:            6,
		MaxLength:            4096,
	}
}

// ValidatePassword evaluates a password against the given policy and returns missing criteria.
func ValidatePassword(p PasswordPolicy, password string) []string {
	var missing []string

	minLen := p.MinLength
	if minLen < 6 {
		minLen = 6
	}
	maxLen := p.MaxLength
	if maxLen < minLen || maxLen > 4096 {
		maxLen = 4096
	}

	length := len(password)
	if length < minLen {
		missing = append(missing, "min_length")
	}
	if length > maxLen {
		missing = append(missing, "max_length")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if p.RequireUppercase && !hasUpper {
		missing = append(missing, "require_uppercase")
	}
	if p.RequireLowercase && !hasLower {
		missing = append(missing, "require_lowercase")
	}
	if p.RequireNumeric && !hasDigit {
		missing = append(missing, "require_numeric")
	}
	if p.RequireSpecial && !hasSpecial {
		missing = append(missing, "require_special")
	}

	return missing
}
