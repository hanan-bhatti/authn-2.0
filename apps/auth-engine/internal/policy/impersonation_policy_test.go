/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/impersonation_policy_test.go
 * Tier: Domain Model Layer / Policy Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy_test

import (
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/stretchr/testify/assert"
)

func TestImpersonationPolicyValidation(t *testing.T) {
	defaultPol := policy.DefaultImpersonationPolicy()
	assert.NoError(t, policy.ValidateImpersonationPolicy(defaultPol))

	// Invalid Duration Bounds (< 1 or > 60)
	invalidLowDuration := defaultPol
	invalidLowDuration.MaxDurationMinutes = 0
	assert.Error(t, policy.ValidateImpersonationPolicy(invalidLowDuration))

	invalidHighDuration := defaultPol
	invalidHighDuration.MaxDurationMinutes = 61
	assert.Error(t, policy.ValidateImpersonationPolicy(invalidHighDuration))

	// Invalid Email Policy
	invalidEmailPol := defaultPol
	invalidEmailPol.EmailNotificationPolicy = "UNKNOWN"
	assert.Error(t, policy.ValidateImpersonationPolicy(invalidEmailPol))
}

func TestValidateImpersonateRequest(t *testing.T) {
	pol := policy.DefaultImpersonationPolicy() // max_duration = 15, require_ticket_id = false

	// 1. Valid Request
	validReq := policy.ImpersonateRequest{
		Reason:          "Investigating user billing bug",
		DurationMinutes: 10,
	}
	assert.NoError(t, policy.ValidateImpersonateRequest(validReq, pol))

	// 2. Reason too short (< 10 chars)
	shortReasonReq := policy.ImpersonateRequest{
		Reason: "test",
	}
	err := policy.ValidateImpersonateRequest(shortReasonReq, pol)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 10 characters")

	// 3. Duration exceeds max allowed
	excessiveDurReq := policy.ImpersonateRequest{
		Reason:          "Investigating user billing bug",
		DurationMinutes: 30, // exceeds pol.MaxDurationMinutes (15)
	}
	err = policy.ValidateImpersonateRequest(excessiveDurReq, pol)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be between 1 and 15 minutes")

	// 4. Ticket ID required by policy
	strictPol := pol
	strictPol.RequireTicketID = true

	noTicketReq := policy.ImpersonateRequest{
		Reason: "Investigating user billing bug",
	}
	err = policy.ValidateImpersonateRequest(noTicketReq, strictPol)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ticket_id is required")

	withTicketReq := policy.ImpersonateRequest{
		Reason:   "Investigating user billing bug",
		TicketID: "TICK-4092",
	}
	assert.NoError(t, policy.ValidateImpersonateRequest(withTicketReq, strictPol))
}
