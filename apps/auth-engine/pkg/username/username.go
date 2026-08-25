/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/username/username.go
 * Tier: Shared Package / Identifier Normalization
 *
 * Canonicalization and validation of the public username handle.
 *
 * A username is displayed to other people, typed by hand, and — once it is a
 * sign-in identifier — names an account. All three make visual ambiguity a
 * security property rather than a cosmetic one: if two distinct handles can
 * render identically, one impersonates the other and no amount of care at the
 * call site prevents it.
 *
 * Two rules close that off. The stored canonical form is NFKC-composed and
 * lower-cased, so "AlexSmith" and "alexsmith" are one handle rather than two.
 * The canonical charset is restricted to ASCII letters, digits and underscore,
 * which removes the confusable problem at the door instead of folding homoglyph
 * pairs after the fact — Cyrillic "а" (U+0430) is visually identical to Latin
 * "a" and no fold enumerates every such pair correctly. The restriction also
 * makes a handle safe in a URL path and in an @-mention without escaping.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package username

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Length bounds on the canonical form, measured in characters. The canonical
// charset is ASCII, so for the stored value characters and bytes agree and the
// distinction only matters for the raw input measured before normalization.
//
// Thirty is a display bound: a handle appears in mention lists and member tables
// where an arbitrarily long one breaks the layout of every row beside it. Three
// is the shortest that leaves a usable namespace while keeping one- and
// two-character handles — which are scarce and disproportionately valuable —
// out of first-come-first-served allocation.
const (
	MinLength = 3
	MaxLength = 30
)

// MaxInputBytes is the largest raw value the package will normalize.
//
// NFKC can expand its input several times over, so normalizing an unbounded
// field would let a small request allocate a large string on a path that
// otherwise rejects an over-long handle without spending anything. The value is
// four bytes per character at the character ceiling, which is the most a handle
// of the maximum length can occupy.
const MaxInputBytes = MaxLength * 4

// Validation failures, one per rule, so a caller can render the specific reason
// rather than a single opaque "invalid username". A form that says only "invalid"
// leaves the user guessing which of five rules they broke.
var (
	ErrEmpty          = errors.New("username is empty")
	ErrTooShort       = errors.New("username is too short")
	ErrTooLong        = errors.New("username is too long")
	ErrCharset        = errors.New("username contains characters that are not allowed")
	ErrLeadingChar    = errors.New("username must start with a letter")
	ErrTrailingChar   = errors.New("username must not end with an underscore")
	ErrReservedHandle = errors.New("username is reserved")
)

// Canonical returns the storage and lookup form of raw.
//
// The result is NFKC-composed, lower-cased, and guaranteed to satisfy every rule
// the package enforces, which is what lets a caller compare it against a stored
// value directly instead of through LOWER() — an expression no index can serve,
// turning what should be one index seek into a full table scan.
//
// Returns one of the package's errors describing the first rule broken. A
// reserved handle is reported by ErrReservedHandle even though it is otherwise
// well-formed, so a caller that wants the distinction can test for it.
func Canonical(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrEmpty
	}
	if len(trimmed) > MaxInputBytes {
		return "", ErrTooLong
	}

	// Normalization precedes the charset check so that a fullwidth "ａ" is folded
	// to "a" and accepted rather than refused as a disallowed character. Checking
	// first would reject input that is, once composed, perfectly valid ASCII.
	folded := strings.ToLower(norm.NFKC.String(trimmed))

	runes := []rune(folded)
	if len(runes) < MinLength {
		return "", ErrTooShort
	}
	if len(runes) > MaxLength {
		return "", ErrTooLong
	}

	// The charset is tested before the positional rules so that a handle led by a
	// character outside the charset is reported as a charset failure. A Cyrillic
	// "а" is a letter, and reporting "must start with a letter" for it would tell
	// the user their input satisfies the rule it just failed.
	for _, r := range runes {
		if !isAllowed(r) {
			return "", ErrCharset
		}
	}
	if !isLetter(runes[0]) {
		return "", ErrLeadingChar
	}
	if runes[len(runes)-1] == '_' {
		return "", ErrTrailingChar
	}
	if Reserved(folded) {
		return "", ErrReservedHandle
	}
	return folded, nil
}

// Valid reports whether raw canonicalizes without error, for callers that need
// the verdict and not the value.
func Valid(raw string) bool {
	_, err := Canonical(raw)
	return err == nil
}

// Explain renders a validation error as the sentence shown to the person who
// typed the handle.
//
// The wording lives beside the rules rather than at each call site so that a rule
// and its explanation cannot drift apart, and so the message a user sees does not
// depend on which endpoint they reached. Each sentence names the fix rather than
// the violation: "must start with a letter" tells the user what to type, where
// "invalid leading character" tells them only that they were wrong.
//
// An unrecognised error yields the general rule statement, which is correct for
// any failure this package can produce.
func Explain(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrEmpty):
		return "username is required"
	case errors.Is(err, ErrTooShort):
		return fmt.Sprintf("username must be at least %d characters", MinLength)
	case errors.Is(err, ErrTooLong):
		return fmt.Sprintf("username must be at most %d characters", MaxLength)
	case errors.Is(err, ErrCharset):
		return "username may contain only letters, digits and underscores"
	case errors.Is(err, ErrLeadingChar):
		return "username must start with a letter"
	case errors.Is(err, ErrTrailingChar):
		return "username must not end with an underscore"
	case errors.Is(err, ErrReservedHandle):
		return "username is reserved and cannot be registered"
	default:
		return fmt.Sprintf("username must be %d-%d characters of letters, digits and underscores, "+
			"start with a letter, and not be a reserved word", MinLength, MaxLength)
	}
}

// Reason classifies a validation error for the availability response's machine
// readable field, collapsing the individual rules into the two outcomes a client
// branches on. A caller distinguishes a handle that could never be granted from
// one that is merely held by somebody else, and does not need to know which of six
// rules produced the former.
func Reason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrReservedHandle):
		return ReasonReserved
	default:
		return ReasonInvalid
	}
}

// Machine readable values for the availability response's reason field.
const (
	// ReasonInvalid marks a handle that breaks one of the structural rules.
	ReasonInvalid = "invalid"
	// ReasonReserved marks a well-formed handle withheld from allocation.
	ReasonReserved = "reserved"
	// ReasonTaken marks a well-formed handle held by another account. It is
	// produced by the availability path rather than by validation, and is named
	// here so the three values are declared together.
	ReasonTaken = "taken"
)

// isAllowed reports whether r may appear in a canonical handle.
func isAllowed(r rune) bool {
	return isLetter(r) || (r >= '0' && r <= '9') || r == '_'
}

// isLetter reports whether r is a lower-case ASCII letter. Canonical lower-cases
// before calling this, so an upper-case letter never reaches it.
func isLetter(r rune) bool {
	return r >= 'a' && r <= 'z'
}
