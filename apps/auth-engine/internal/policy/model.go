/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/model.go
 * Tier: Domain Model Layer
 *
 * Tenant policy definitions and their validation: password complexity, security
 * enforcement, account recovery, and impersonation governance.
 *
 * Each policy has a Default* constructor and, where its fields interact, a
 * Validate* function. Defaults are the behaviour of a tenant that has configured
 * nothing, so they are chosen to be safe rather than permissive. Validation is
 * the boundary for caller-supplied policy: bounds are enforced here, once, so no
 * consumer has to re-check what a stored policy contains.
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
	// EnforcementMode is "require" to reject non-compliant passwords or "notify"
	// to accept them and report what is missing.
	EnforcementMode string `json:"enforcement_mode"`
	// RequireUppercase demands at least one A-Z character.
	RequireUppercase bool `json:"require_uppercase"`
	// RequireLowercase demands at least one a-z character.
	RequireLowercase bool `json:"require_lowercase"`
	// RequireNumeric demands at least one digit.
	RequireNumeric bool `json:"require_numeric"`
	// RequireSpecial demands at least one punctuation or symbol character.
	RequireSpecial bool `json:"require_special"`
	// ForceUpgradeOnSignin makes an existing user with a non-compliant password
	// set a new one at their next sign-in.
	ForceUpgradeOnSignin bool `json:"force_upgrade_on_signin"`
	// MinLength is the minimum character count. ValidatePassword floors it at 8
	// whatever is stored.
	MinLength int `json:"min_length"`
	// MaxLength is the maximum character count, capped at 4096. The cap exists
	// because hashing is deliberately expensive: an unbounded password is a
	// unbounded amount of work per login attempt.
	MaxLength int `json:"max_length"`
}

// DefaultPasswordPolicy returns the password policy applied to a tenant that has
// configured none: eight characters with at least one digit, enforced.
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
	// RequireEmailVerification gates access on a verified email address.
	RequireEmailVerification bool `json:"require_email_verification"`
	// EmailVerificationMode is "hard" to block an unverified user with 403, or
	// "soft" to admit them with the unverified state flagged on the token.
	EmailVerificationMode string `json:"email_verification_mode"`
	// TokenReusePolicy is the response to a replayed refresh token:
	// "global_revoke" ends every session the user has, "session_revoke" ends only
	// the affected token family. Global revocation is the default because a
	// replayed token means the token store is compromised, and the blast radius
	// of guessing wrong is a forced re-login rather than a retained intruder.
	TokenReusePolicy string `json:"token_reuse_policy"`
}

// DefaultSecurityPolicy returns the security policy applied to a tenant that has
// configured none: verification encouraged but not enforced, and a replayed
// refresh token revoking every session.
func DefaultSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		RequireEmailVerification: false,
		EmailVerificationMode:    "soft",
		TokenReusePolicy:         "global_revoke",
	}
}

// RecoveryPolicy defines tenant-level account recovery rules: which proofs are
// accepted, how long each stage lasts, and how aggressively repeated failures
// are locked out.
type RecoveryPolicy struct {
	// GuardiansEnabled accepts vouching by enrolled guardians as a recovery proof.
	GuardiansEnabled bool `json:"guardians_enabled"`
	// PhoneOTPEnabled accepts a one-time code sent by SMS.
	PhoneOTPEnabled bool `json:"phone_otp_enabled"`
	// EmailOTPEnabled accepts a one-time code sent to the recovery address.
	EmailOTPEnabled bool `json:"email_otp_enabled"`
	// OldPasswordEnabled accepts a previously valid password.
	OldPasswordEnabled bool `json:"old_password_enabled"`
	// SecurityQuestionsEnabled accepts answers to enrolled security questions.
	SecurityQuestionsEnabled bool `json:"security_questions_enabled"`

	// FreezeWindowHours is how long an account stays frozen after a recovery is
	// initiated, giving the real owner time to intervene before control changes
	// hands. Range 24-168.
	FreezeWindowHours int `json:"freeze_window_hours"`
	// ClaimTokenTTLMinutes is the lifetime of the token that completes a
	// recovery. Range 5-60.
	ClaimTokenTTLMinutes int `json:"claim_token_ttl_minutes"`
	// LockoutSchedule is the escalating lockout applied to repeated failed
	// recovery attempts, as duration steps ("24h", "3d", "4w", "permanent"),
	// monotonically non-decreasing. Between 3 and 10 steps.
	LockoutSchedule []string `json:"lockout_schedule"`
	// LockoutResetDays is how long a clean record must last before the escalation
	// level returns to zero. Range 7-90.
	LockoutResetDays int `json:"lockout_reset_days"`
	// TrustedDeviceWindowDays is how long a device stays trusted for recovery
	// purposes. Range 30-365.
	TrustedDeviceWindowDays int `json:"trusted_device_window_days"`

	// MinGuardians is the fewest guardians a user must enrol. At least 1.
	MinGuardians int `json:"min_guardians"`
	// MaxGuardians is the most a user may enrol. At most 5.
	MaxGuardians int `json:"max_guardians"`

	// IPv4SubnetBits is the prefix length recovery attempts are grouped by when
	// the source is IPv4, so an attacker cannot look like a new network by
	// changing the last octet. Range 16-30.
	IPv4SubnetBits int `json:"ipv4_subnet_bits"`
	// IPv6SubnetBits is the same for IPv6, where a single customer is routinely
	// assigned a whole prefix. Range 32-64.
	IPv6SubnetBits int `json:"ipv6_subnet_bits"`
	// MaxProofAttemptsPerWindow caps recovery proof attempts per window. Range 1-10.
	MaxProofAttemptsPerWindow int `json:"max_proof_attempts_per_window"`
}

// DefaultRecoveryPolicy returns the recovery policy applied to a tenant that has
// configured none: every method available, a two-day freeze, and lockouts
// escalating from a day to permanent.
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

// minLockoutFirstStep is the shortest permitted opening step of a lockout
// schedule. A first step below this makes the escalation ineffective: an
// attacker simply waits it out between attempts.
const minLockoutFirstStep = 1 * time.Hour

// ValidateRecoveryPolicy checks every field of a RecoveryPolicy against its
// documented bounds and returns the first violation, naming the field and the
// value seen. It returns nil when the policy is storable.
//
// Two rules are structural rather than numeric: at least one recovery method
// must stay enabled, or no user could ever recover an account; and the lockout
// schedule must be monotonically non-decreasing, or a later offence would be
// punished more lightly than an earlier one.
func ValidateRecoveryPolicy(p RecoveryPolicy) error {
	if !p.GuardiansEnabled && !p.PhoneOTPEnabled && !p.EmailOTPEnabled && !p.OldPasswordEnabled && !p.SecurityQuestionsEnabled {
		return errors.New("at least one recovery method toggle must remain enabled tenant-wide")
	}

	if p.FreezeWindowHours < 24 || p.FreezeWindowHours > 168 {
		return fmt.Errorf("freeze_window_hours must be between 24 and 168 (got %d)", p.FreezeWindowHours)
	}

	if p.ClaimTokenTTLMinutes < 5 || p.ClaimTokenTTLMinutes > 60 {
		return fmt.Errorf("claim_token_ttl_minutes must be between 5 and 60 (got %d)", p.ClaimTokenTTLMinutes)
	}

	if len(p.LockoutSchedule) < 3 || len(p.LockoutSchedule) > 10 {
		return fmt.Errorf("lockout_schedule must contain between 3 and 10 steps (got %d)", len(p.LockoutSchedule))
	}

	var prevDur time.Duration
	for i, step := range p.LockoutSchedule {
		dur, err := parseLockoutStepDuration(step)
		if err != nil {
			return fmt.Errorf("lockout_schedule step [%d] invalid: %w", i, err)
		}
		if i == 0 && dur < minLockoutFirstStep {
			return fmt.Errorf("lockout_schedule first step must be at least 1h (got %s)", step)
		}
		if i > 0 && dur < prevDur {
			return fmt.Errorf("lockout_schedule step [%d] (%s) is shorter than previous step [%d] (%s) — schedule must be monotonically non-decreasing",
				i, step, i-1, p.LockoutSchedule[i-1])
		}
		prevDur = dur
	}

	if p.LockoutResetDays < 7 || p.LockoutResetDays > 90 {
		return fmt.Errorf("lockout_reset_days must be between 7 and 90 (got %d)", p.LockoutResetDays)
	}

	if p.TrustedDeviceWindowDays < 30 || p.TrustedDeviceWindowDays > 365 {
		return fmt.Errorf("trusted_device_window_days must be between 30 and 365 (got %d)", p.TrustedDeviceWindowDays)
	}

	if p.MinGuardians < 1 {
		return fmt.Errorf("min_guardians must be >= 1 (got %d)", p.MinGuardians)
	}
	if p.MaxGuardians > 5 {
		return fmt.Errorf("max_guardians must be <= 5 (got %d)", p.MaxGuardians)
	}
	if p.MinGuardians > p.MaxGuardians {
		return fmt.Errorf("min_guardians (%d) cannot exceed max_guardians (%d)", p.MinGuardians, p.MaxGuardians)
	}

	if p.IPv4SubnetBits < 16 || p.IPv4SubnetBits > 30 {
		return fmt.Errorf("ipv4_subnet_bits must be between 16 and 30 (got %d)", p.IPv4SubnetBits)
	}
	if p.IPv6SubnetBits < 32 || p.IPv6SubnetBits > 64 {
		return fmt.Errorf("ipv6_subnet_bits must be between 32 and 64 (got %d)", p.IPv6SubnetBits)
	}

	if p.MaxProofAttemptsPerWindow < 1 || p.MaxProofAttemptsPerWindow > 10 {
		return fmt.Errorf("max_proof_attempts_per_window must be between 1 and 10 (got %d)", p.MaxProofAttemptsPerWindow)
	}

	return nil
}

// parseLockoutStepDuration converts one lockout-schedule step into a duration.
//
// It accepts "permanent" (the maximum representable duration), a week count
// suffixed "w", a day count suffixed "d", and otherwise anything
// time.ParseDuration accepts. Weeks and days are spelled out here because Go's
// parser stops at hours. It returns an error for an unparseable step and for any
// step that is zero or negative, since a non-positive lockout is no lockout.
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

// ValidatePassword evaluates a password against a policy and returns the names
// of the criteria it fails — "min_length", "max_length", "require_uppercase",
// "require_lowercase", "require_numeric", "require_special" — or nil when it
// satisfies all of them. The caller decides what a failure means: "require"
// rejects, "notify" reports.
//
// The policy's own bounds are floored at 8 and capped at 4096 here, so a stored
// policy weakened below the engine's own minimum cannot admit a shorter password.
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

// ImpersonationPolicy defines tenant-level governance for admin impersonation.
type ImpersonationPolicy struct {
	// Enabled is the tenant's master switch for the feature.
	Enabled bool `json:"enabled"`
	// MaxDurationMinutes caps an impersonation session, 1-60. A request may ask
	// for less but never more.
	MaxDurationMinutes int `json:"max_duration_minutes"`
	// RequireStepUpAuth demands the admin re-prove their own identity —
	// password, TOTP or passkey — at the moment of the request, so a borrowed
	// console tab cannot start a session.
	RequireStepUpAuth bool `json:"require_step_up_auth"`
	// RequireTicketID demands a support ticket reference, tying each session to
	// a record outside the engine.
	RequireTicketID bool `json:"require_ticket_id"`
	// RequireUserOptIn demands the target's support_access_enabled flag.
	RequireUserOptIn bool `json:"require_user_opt_in"`
	// EmailNotificationPolicy is when the target is told: "IMMEDIATE",
	// "POST_SESSION" or "DISABLED".
	EmailNotificationPolicy string `json:"email_notification_policy"`
	// ReadOnlyDefault forces impersonation tokens into read-only mode.
	ReadOnlyDefault bool `json:"read_only_default"`
	// RestrictAdminImpersonation blocks impersonating users who hold
	// administrative roles, so the feature cannot be used to climb privilege.
	RestrictAdminImpersonation bool `json:"restrict_admin_impersonation"`
	// AllowedRoles lists the role slugs permitted to impersonate.
	AllowedRoles []string `json:"allowed_roles"`
}

// DefaultImpersonationPolicy returns the impersonation policy applied to a
// tenant that has configured none: enabled, capped at fifteen minutes, step-up
// required, administrators protected, and the target notified immediately.
func DefaultImpersonationPolicy() ImpersonationPolicy {
	return ImpersonationPolicy{
		Enabled:                    true,
		MaxDurationMinutes:         15,
		RequireStepUpAuth:          true,
		RequireTicketID:            false,
		RequireUserOptIn:           false,
		EmailNotificationPolicy:    "IMMEDIATE",
		ReadOnlyDefault:            false,
		RestrictAdminImpersonation: true,
		AllowedRoles:               []string{"tenant_admin", "support_admin"},
	}
}

// ValidateImpersonationPolicy checks an ImpersonationPolicy's bounds, returning
// an error when the duration cap falls outside 1-60 minutes or the notification
// policy is not one of the three recognised values, and nil otherwise.
func ValidateImpersonationPolicy(pol ImpersonationPolicy) error {
	if pol.MaxDurationMinutes < 1 || pol.MaxDurationMinutes > 60 {
		return errors.New("max_duration_minutes must be between 1 and 60 minutes")
	}
	validEmailPolicies := map[string]bool{
		"IMMEDIATE":    true,
		"POST_SESSION": true,
		"DISABLED":     true,
	}
	if !validEmailPolicies[pol.EmailNotificationPolicy] {
		return fmt.Errorf("invalid email_notification_policy '%s': must be IMMEDIATE, POST_SESSION, or DISABLED", pol.EmailNotificationPolicy)
	}
	return nil
}

// ImpersonateRequest is the payload for initiating an impersonation session.
type ImpersonateRequest struct {
	// Reason is the operator's justification, 10-500 characters, recorded in the
	// audit trail and shown to the user in the notification.
	Reason string `json:"reason"`
	// DurationMinutes is the requested session length. Zero takes the policy cap;
	// anything above it is clamped down to the cap.
	DurationMinutes int `json:"duration_minutes,omitempty"`
	// TicketID references the support ticket, 3-100 characters when present.
	TicketID string `json:"ticket_id,omitempty"`
	// VerificationMethod selects the step-up proof: "password", "totp",
	// "webauthn" or "passkey".
	VerificationMethod string `json:"verification_method,omitempty"`
	// MFACode is the TOTP code for "totp" step-up.
	MFACode string `json:"mfa_code,omitempty"`
	// AdminPassword is the admin's own password for "password" step-up.
	AdminPassword string `json:"admin_password,omitempty"`
	// CredentialID identifies the passkey for "webauthn"/"passkey" step-up.
	CredentialID string `json:"credential_id,omitempty"`
}

// ValidateImpersonateRequest checks a request against the tenant's policy,
// returning an error naming the first field at fault and nil when the request is
// acceptable.
//
// The reason is mandatory and length-bounded because it is the audit record of
// why a support agent entered someone's account. A ticket ID is bounded whenever
// it is supplied, whether or not policy requires one, so an optional field
// cannot be used to smuggle unbounded text into the trail.
func ValidateImpersonateRequest(req ImpersonateRequest, pol ImpersonationPolicy) error {
	reason := strings.TrimSpace(req.Reason)
	if len(reason) < 10 {
		return errors.New("reason is required and must be at least 10 characters")
	}
	if len(reason) > 500 {
		return errors.New("reason must not exceed 500 characters")
	}

	if pol.RequireTicketID {
		ticketID := strings.TrimSpace(req.TicketID)
		if ticketID == "" {
			return errors.New("ticket_id is required by active tenant impersonation policy")
		}
		if len(ticketID) < 3 || len(ticketID) > 100 {
			return errors.New("ticket_id must be between 3 and 100 characters")
		}
	} else if req.TicketID != "" {
		ticketID := strings.TrimSpace(req.TicketID)
		if len(ticketID) < 3 || len(ticketID) > 100 {
			return errors.New("ticket_id must be between 3 and 100 characters")
		}
	}

	duration := req.DurationMinutes
	if duration <= 0 {
		duration = pol.MaxDurationMinutes
	}
	if duration < 1 || duration > pol.MaxDurationMinutes {
		return fmt.Errorf("requested duration_minutes (%d) must be between 1 and %d minutes", duration, pol.MaxDurationMinutes)
	}

	return nil
}
