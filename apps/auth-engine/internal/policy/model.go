/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/model.go
 * Tier: Domain Model Layer
 *
 * Description: Password, Security, and Recovery policy definitions and validation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// PasswordPolicy defines tenant-level password complexity requirements.
type PasswordPolicy struct {
	EnforcementMode      string `json:"enforcement_mode"`        // "require" (default) | "notify"
	RequireUppercase     bool   `json:"require_uppercase"`       // Must contain A-Z
	RequireLowercase     bool   `json:"require_lowercase"`       // Must contain a-z
	RequireNumeric       bool   `json:"require_numeric"`         // Must contain 0-9
	RequireSpecial       bool   `json:"require_special"`         // Must contain special symbols
	ForceUpgradeOnSignin bool   `json:"force_upgrade_on_signin"` // Require upgrade on signin if non-compliant
	MinLength            int    `json:"min_length"`              // Minimum character length (default: 6)
	MaxLength            int    `json:"max_length"`              // Maximum character length (default: 4096)
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
		MinLength:            8,
		MaxLength:            4096,
	}
}

// SecurityPolicy defines tenant-level security enforcement settings.
type SecurityPolicy struct {
	RequireEmailVerification bool   `json:"require_email_verification"` // Enforce email verification for users
	EmailVerificationMode    string `json:"email_verification_mode"`    // "hard" (403 block) | "soft" (allow login with warning/token flag)
}

// DefaultSecurityPolicy returns standard default security policy settings.
func DefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		RequireEmailVerification: false,
		EmailVerificationMode:    "soft",
	}
}

// RecoveryPolicy defines tenant-level account recovery rules, method toggles, and security limits.
type RecoveryPolicy struct {
	// 1. Method Enablement Toggles
	GuardiansEnabled         bool `json:"guardians_enabled"`
	PhoneOTPEnabled          bool `json:"phone_otp_enabled"`
	EmailOTPEnabled          bool `json:"email_otp_enabled"`
	OldPasswordEnabled       bool `json:"old_password_enabled"`
	SecurityQuestionsEnabled bool `json:"security_questions_enabled"`

	// 2. Configurable Timing & Window Durations
	FreezeWindowHours       int      `json:"freeze_window_hours"`        // default: 48 hours
	ClaimTokenTTLMinutes    int      `json:"claim_token_ttl_minutes"`    // default: 15 minutes
	LockoutSchedule         []string `json:"lockout_schedule"`           // default: ["24h","3d","7d","14d","4w","8w","12w","permanent"]
	LockoutResetDays        int      `json:"lockout_reset_days"`         // default: 30 days
	TrustedDeviceWindowDays int      `json:"trusted_device_window_days"` // default: 90 days

	// 3. Guardian Enrolment Boundaries
	MinGuardians int `json:"min_guardians"` // default: 1
	MaxGuardians int `json:"max_guardians"` // default: 5

	// 4. Additional Configurable Audit Parameters
	IPv4SubnetBits            int `json:"ipv4_subnet_bits"`             // default: 24 (masks to /24)
	IPv6SubnetBits            int `json:"ipv6_subnet_bits"`             // default: 48 (masks to /48)
	MaxProofAttemptsPerWindow int `json:"max_proof_attempts_per_window"` // default: 3 attempts per 10 min window
}

// DefaultRecoveryPolicy returns standard initial account recovery policy settings.
func DefaultRecoveryPolicy() RecoveryPolicy {
	return RecoveryPolicy{
		GuardiansEnabled:          true,
		PhoneOTPEnabled:           true,
		EmailOTPEnabled:           true,
		OldPasswordEnabled:        true,
		SecurityQuestionsEnabled:  true,
		FreezeWindowHours:         48,
		ClaimTokenTTLMinutes:      15,
		LockoutSchedule:           []string{"24h", "3d", "7d", "14d", "4w", "8w", "12w", "permanent"},
		LockoutResetDays:          30,
		TrustedDeviceWindowDays:   90,
		MinGuardians:              1,
		MaxGuardians:              5,
		IPv4SubnetBits:            24,
		IPv6SubnetBits:            48,
		MaxProofAttemptsPerWindow: 3,
	}
}

// ValidateRecoveryPolicy evaluates all fields, boundary limits, and schedule ordering of a RecoveryPolicy.
func ValidateRecoveryPolicy(p RecoveryPolicy) error {
	// Rule 7: At least ONE method-enabled toggle must remain true tenant-wide
	if !p.GuardiansEnabled && !p.PhoneOTPEnabled && !p.EmailOTPEnabled && !p.OldPasswordEnabled && !p.SecurityQuestionsEnabled {
		return errors.New("at least one recovery method toggle must remain enabled tenant-wide")
	}

	// Rule 1: freeze_window_hours (min 24, max 168)
	if p.FreezeWindowHours < 24 || p.FreezeWindowHours > 168 {
		return fmt.Errorf("freeze_window_hours must be between 24 and 168 (got %d)", p.FreezeWindowHours)
	}

	// Rule 2: claim_token_ttl_minutes (min 5, max 60)
	if p.ClaimTokenTTLMinutes < 5 || p.ClaimTokenTTLMinutes > 60 {
		return fmt.Errorf("claim_token_ttl_minutes must be between 5 and 60 (got %d)", p.ClaimTokenTTLMinutes)
	}

	// Rule 3: lockout_schedule (between 3 and 10 steps, first step >= 1h, monotonically non-decreasing)
	if len(p.LockoutSchedule) < 3 || len(p.LockoutSchedule) > 10 {
		return fmt.Errorf("lockout_schedule must contain between 3 and 10 steps (got %d)", len(p.LockoutSchedule))
	}

	var prevDur time.Duration
	for i, step := range p.LockoutSchedule {
		dur, err := parseLockoutStepDuration(step)
		if err != nil {
			return fmt.Errorf("lockout_schedule step [%d] invalid: %w", i, err)
		}
		if i == 0 && dur < 1*time.Hour {
			return fmt.Errorf("lockout_schedule first step must be at least 1h (got %s)", step)
		}
		if i > 0 && dur < prevDur {
			return fmt.Errorf("lockout_schedule step [%d] (%s) is shorter than previous step [%d] (%s) — schedule must be monotonically non-decreasing",
				i, step, i-1, p.LockoutSchedule[i-1])
		}
		prevDur = dur
	}

	// Rule 4: lockout_reset_days (min 7, max 90)
	if p.LockoutResetDays < 7 || p.LockoutResetDays > 90 {
		return fmt.Errorf("lockout_reset_days must be between 7 and 90 (got %d)", p.LockoutResetDays)
	}

	// Rule 5: trusted_device_window_days (min 30, max 365)
	if p.TrustedDeviceWindowDays < 30 || p.TrustedDeviceWindowDays > 365 {
		return fmt.Errorf("trusted_device_window_days must be between 30 and 365 (got %d)", p.TrustedDeviceWindowDays)
	}

	// Rule 6: min_guardians & max_guardians boundaries
	if p.MinGuardians < 1 {
		return fmt.Errorf("min_guardians must be >= 1 (got %d)", p.MinGuardians)
	}
	if p.MaxGuardians > 5 {
		return fmt.Errorf("max_guardians must be <= 5 (got %d)", p.MaxGuardians)
	}
	if p.MinGuardians > p.MaxGuardians {
		return fmt.Errorf("min_guardians (%d) cannot exceed max_guardians (%d)", p.MinGuardians, p.MaxGuardians)
	}

	// Rule 8: Subnet bit boundaries (IPv4: 16-30, IPv6: 32-64)
	if p.IPv4SubnetBits < 16 || p.IPv4SubnetBits > 30 {
		return fmt.Errorf("ipv4_subnet_bits must be between 16 and 30 (got %d)", p.IPv4SubnetBits)
	}
	if p.IPv6SubnetBits < 32 || p.IPv6SubnetBits > 64 {
		return fmt.Errorf("ipv6_subnet_bits must be between 32 and 64 (got %d)", p.IPv6SubnetBits)
	}

	// Rule 9: max_proof_attempts_per_window (min 1, max 10)
	if p.MaxProofAttemptsPerWindow < 1 || p.MaxProofAttemptsPerWindow > 10 {
		return fmt.Errorf("max_proof_attempts_per_window must be between 1 and 10 (got %d)", p.MaxProofAttemptsPerWindow)
	}

	return nil
}

func parseLockoutStepDuration(step string) (time.Duration, error) {
	step = strings.ToLower(strings.TrimSpace(step))
	if step == "permanent" {
		return time.Duration(1<<63 - 1), nil
	}
	if strings.HasSuffix(step, "w") {
		weeks, err := strconv.Atoi(strings.TrimSuffix(step, "w"))
		if err != nil || weeks <= 0 {
			return 0, fmt.Errorf("invalid week step: %s", step)
		}
		return time.Duration(weeks) * 7 * 24 * time.Hour, nil
	}
	if strings.HasSuffix(step, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(step, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day step: %s", step)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	dur, err := time.ParseDuration(step)
	if err != nil || dur <= 0 {
		return 0, fmt.Errorf("invalid duration step: %s", step)
	}
	return dur, nil
}

// ValidatePassword evaluates a password against the given policy and returns missing criteria.
func ValidatePassword(p PasswordPolicy, password string) []string {
	var missing []string

	minLen := p.MinLength
	if minLen < 8 {
		minLen = 8
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
