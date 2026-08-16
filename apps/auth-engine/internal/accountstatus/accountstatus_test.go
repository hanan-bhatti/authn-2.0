/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/accountstatus/accountstatus_test.go
 * Tier: Domain Layer / Account Eligibility
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package accountstatus_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/accountstatus"
)

// TestOnlyAnActiveAccountIsAllowed pins the eligibility table. Each status maps
// to one sentinel, and the mapping is the whole contract every sign-in path
// depends on, so a status silently becoming permitted has to fail here.
func TestOnlyAnActiveAccountIsAllowed(t *testing.T) {
	cases := []struct {
		name   string
		user   *ent.User
		expect error
	}{
		{"active", &ent.User{Status: user.StatusActive}, nil},
		{"banned", &ent.User{Status: user.StatusBanned}, accountstatus.ErrBanned},
		{"suspended", &ent.User{Status: user.StatusSuspended}, accountstatus.ErrSuspended},
		{"recovery hold", &ent.User{Status: user.StatusRecoveryHold}, accountstatus.ErrRecoveryHold},
		{"unrecognised status", &ent.User{Status: user.Status("archived")}, accountstatus.ErrUnknownStatus},
		{"nil user", nil, accountstatus.ErrDeleted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := accountstatus.Allowed(tc.user)
			if !errors.Is(got, tc.expect) {
				t.Fatalf("Allowed(%s) = %v, want %v", tc.name, got, tc.expect)
			}
		})
	}
}

// TestSoftDeletionOutranksAnActiveStatus covers the row that keeps an address
// reserved after the account is gone. Its status is left untouched by deletion,
// so a check that read status alone would admit it.
func TestSoftDeletionOutranksAnActiveStatus(t *testing.T) {
	deletedAt := time.Now().Add(-time.Hour)
	u := &ent.User{Status: user.StatusActive, DeletedAt: &deletedAt}

	if err := accountstatus.Allowed(u); !errors.Is(err, accountstatus.ErrDeleted) {
		t.Fatalf("Allowed(soft-deleted but active) = %v, want ErrDeleted", err)
	}
}

// TestRefusedSeparatesEligibilityFromInfrastructure checks the predicate every
// handler branches on. It has to answer true for all five refusals and false for
// anything else, or a storage failure would be rendered to a caller as a ban.
func TestRefusedSeparatesEligibilityFromInfrastructure(t *testing.T) {
	refusals := []error{
		accountstatus.ErrBanned,
		accountstatus.ErrSuspended,
		accountstatus.ErrRecoveryHold,
		accountstatus.ErrDeleted,
		accountstatus.ErrUnknownStatus,
	}
	for _, err := range refusals {
		if !accountstatus.Refused(err) {
			t.Errorf("Refused(%v) = false, want true", err)
		}
		// Also wrapped, because a service that adds context to a refusal on its way
		// up must not stop the handler at the top from recognising it.
		if !accountstatus.Refused(fmt.Errorf("rotate refresh token: %w", err)) {
			t.Errorf("Refused(wrapped %v) = false, want true", err)
		}
	}

	for _, err := range []error{nil, errors.New("connection refused")} {
		if accountstatus.Refused(err) {
			t.Errorf("Refused(%v) = true, want false", err)
		}
	}
}

// TestPublicMessageWithholdsDeletion is the disclosure boundary. A restriction an
// administrator placed is named so the account holder knows retrying will not
// help; a deleted account is not, because confirming it would turn any sign-in
// surface into a way to ask which addresses were once registered here.
func TestPublicMessageWithholdsDeletion(t *testing.T) {
	named := map[error]string{
		accountstatus.ErrBanned:       "banned",
		accountstatus.ErrSuspended:    "suspended",
		accountstatus.ErrRecoveryHold: "recovery",
	}
	for err, want := range named {
		got := accountstatus.PublicMessage(err)
		if !strings.Contains(strings.ToLower(got), want) {
			t.Errorf("PublicMessage(%v) = %q, want it to mention %q", err, got, want)
		}
	}

	for _, err := range []error{accountstatus.ErrDeleted, accountstatus.ErrUnknownStatus} {
		got := strings.ToLower(accountstatus.PublicMessage(err))
		for _, leak := range []string{"delet", "not recognised", "archiv"} {
			if strings.Contains(got, leak) {
				t.Errorf("PublicMessage(%v) = %q, which discloses %q", err, got, leak)
			}
		}
	}
}
