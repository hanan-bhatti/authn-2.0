/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/accountstatus/accountstatus.go
 * Tier: Domain Layer / Account Eligibility
 *
 * The single decision on whether an account may complete an authentication.
 *
 * Every path that mints a token for a user — password, magic link, second
 * factor, passkey, social, refresh, authorization-code exchange — has to make
 * the same call, and each one making it inline is how a status ends up enforced
 * on five paths and honoured on none. A ban that only stops password sign-in is
 * not a ban.
 *
 * The check takes a loaded user and returns a sentinel, so it holds no
 * repository, no config and no context. Callers match with errors.Is and choose
 * what to tell the caller: a status the account holder can act on is worth
 * naming, while a deleted account is not distinguishable from one that never
 * existed.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package accountstatus

import (
	"errors"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

// Sentinel refusals returned by Allowed. Callers match on these with errors.Is
// to pick a message and a status code, so their identity is what matters rather
// than their text.
var (
	// ErrBanned reports a permanently barred account. Lifting it is an
	// administrative act, not something the account holder can retry past.
	ErrBanned = errors.New("account is banned")
	// ErrSuspended reports a reversible hold placed by an administrator.
	ErrSuspended = errors.New("account is suspended")
	// ErrRecoveryHold reports the security freeze that follows an account
	// recovery, during which sign-in is withheld even from the rightful owner.
	ErrRecoveryHold = errors.New("account is under a recovery hold")
	// ErrDeleted reports a soft-deleted account. The row survives so the email
	// stays reserved, but the account is gone as far as sign-in is concerned, so
	// callers should render this as an unknown account rather than name it.
	ErrDeleted = errors.New("account has been deleted")
	// ErrUnknownStatus reports a status value this package does not recognise,
	// which happens when the enum gains a value and this switch is not extended.
	ErrUnknownStatus = errors.New("account status is not recognised")
)

// Allowed reports whether u may complete an authentication, returning nil when
// it may and one of this package's sentinels when it may not.
//
// A nil user is refused as deleted rather than admitted, so a caller that skips
// its own existence check fails closed. An unrecognised status is refused for
// the same reason: a new enum value is far more likely to be a new kind of
// restriction than a new kind of permission.
func Allowed(u *ent.User) error {
	if u == nil {
		return ErrDeleted
	}
	if u.DeletedAt != nil {
		return ErrDeleted
	}

	switch u.Status {
	case user.StatusActive:
		return nil
	case user.StatusBanned:
		return ErrBanned
	case user.StatusSuspended:
		return ErrSuspended
	case user.StatusRecoveryHold:
		return ErrRecoveryHold
	default:
		return ErrUnknownStatus
	}
}

// Refused reports whether err is one of this package's refusals, which lets a
// caller separate "this account may not sign in" from an infrastructure failure
// without enumerating every sentinel.
func Refused(err error) bool {
	return errors.Is(err, ErrBanned) ||
		errors.Is(err, ErrSuspended) ||
		errors.Is(err, ErrRecoveryHold) ||
		errors.Is(err, ErrDeleted) ||
		errors.Is(err, ErrUnknownStatus)
}

// PublicMessage returns prose safe to show whoever is holding the credential.
//
// A restriction an administrator placed is named, because the person facing it
// needs to know that retrying and resetting their password will not help and
// that support is the way out. A deleted account is not named: its row exists
// only to keep the address reserved, so confirming it would turn any sign-in
// surface into a way to ask which addresses were once registered here.
func PublicMessage(err error) string {
	switch {
	case errors.Is(err, ErrBanned):
		return "This account has been banned."
	case errors.Is(err, ErrSuspended):
		return "This account has been suspended. Contact support to restore access."
	case errors.Is(err, ErrRecoveryHold):
		return "This account is temporarily locked while account recovery is in progress."
	default:
		return "This account is not available."
	}
}
