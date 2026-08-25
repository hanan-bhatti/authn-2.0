/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/username/suggest.go
 * Tier: Shared Package / Identifier Normalization
 *
 * Generation of alternative handles for a request that cannot be granted.
 *
 * Generation is deliberately separated from availability. This file produces a
 * pool of well-formed candidates with no knowledge of what is taken; the caller
 * asks the database about the whole pool in one query and keeps the first few
 * that are free. The alternative — generate one, ask, repeat — is the same total
 * work spread across as many round trips as there are candidates, and it is the
 * only part of the username feature whose cost is not already bounded by an
 * index seek.
 *
 * Candidates are ordered closest-first: the salvaged form of what the user typed
 * comes before anything derived from their name, which comes before anything
 * with a suffix bolted on. A suggestion list is only useful if its first entry is
 * the one the user would have picked themselves.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package username

import (
	"math/rand/v2"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// CandidatePoolSize is how many alternatives the availability path generates
// before asking the database which are free.
//
// The pool is probed with a single batched predicate, so its size sets the work
// for that query and nothing else — twenty-four index entries is indistinguishable
// from one at any table size. It is generous relative to DefaultSuggestions
// because a popular stem has most of its near neighbours taken, and a pool that
// runs dry returns an empty list to a user who is stuck.
const CandidatePoolSize = 24

// DefaultSuggestions is how many free alternatives are returned to the client.
//
// Three fits on one line beneath a form field on a phone. A longer list is a
// decision rather than a hint, and the user already has the one they wanted.
const DefaultSuggestions = 3

// maxNameInputBytes bounds the display name this package will read. The engine
// caps a name at 100 characters elsewhere, and four bytes per character is the
// most those can occupy, so a longer value is malformed rather than long.
const maxNameInputBytes = 100 * 4

// Candidates returns up to n well-formed alternatives derived from seed and,
// where one is supplied, fullName.
//
// Every returned value satisfies Canonical, so a caller may store any of them
// without re-validating. Nothing here is checked for availability: the result is
// the pool to probe, not a list of free handles.
//
// seed is coerced rather than rejected, because the common reason to ask for
// suggestions is that seed was not a valid handle in the first place — "Alex
// Smith" yields "alexsmith" as its first candidate. Returns nil when seed and
// fullName between them contain no usable letters.
func Candidates(seed, fullName string, n int) []string {
	if n <= 0 {
		return nil
	}

	out := make([]string, 0, n)
	seen := make(map[string]struct{}, n)

	// full reports whether the pool is complete, so each generation stage can stop
	// without the caller re-testing the length after every append.
	full := func(candidate string) bool {
		if candidate == "" {
			return len(out) >= n
		}
		if _, dup := seen[candidate]; !dup {
			seen[candidate] = struct{}{}
			if Valid(candidate) {
				out = append(out, candidate)
			}
		}
		return len(out) >= n
	}

	base := slug(seed)
	parts := nameParts(fullName)

	// The salvaged seed first: it is what the user asked for, minus whatever made
	// it unacceptable.
	if full(base) {
		return out
	}

	// Then forms built from the name the user gave at sign-up, which read as
	// deliberate choices rather than as fallbacks.
	if len(parts) >= 2 {
		first, last := parts[0], parts[len(parts)-1]
		for _, candidate := range []string{
			join(first, "_", last),
			join(first, "", last),
			join(first[:1], "", last),
			join(first, "", last[:1]),
			join(last, "_", first),
		} {
			if full(candidate) {
				return out
			}
		}
	}
	if base == "" {
		base = strings.Join(parts, "")
	}
	if base == "" {
		return out
	}

	// Then the seed with a short suffix. Low digits are tried first because they
	// read as intentional where a long random tail reads as generated.
	for i := 1; i <= 3; i++ {
		if full(withSuffix(base, strconv.Itoa(i))) {
			return out
		}
	}
	for i := 1; i <= 2; i++ {
		if full(withSuffix(base, "_"+strconv.Itoa(i))) {
			return out
		}
	}

	// The remainder of the pool is filled with random four-digit tails. A wholly
	// predictable list would hand every user of a popular stem the same
	// alternatives, so the first to submit takes them and the rest see their
	// suggestions fail; spreading the tail across the range makes a collision
	// between two people suggested at the same moment unlikely rather than
	// certain. Attempts are bounded because a duplicate draw produces no new
	// candidate and an unbounded loop on a saturated stem would not terminate.
	for attempts := 0; attempts < n*4; attempts++ {
		if full(withSuffix(base, strconv.Itoa(1000+rand.IntN(9000)))) {
			return out
		}
	}
	return out
}

// withSuffix appends suffix to base, trimming base so the result stays within
// MaxLength. Trimming the base rather than the suffix keeps the suffix's whole
// value, which is what distinguishes one candidate from the next.
func withSuffix(base, suffix string) string {
	if room := MaxLength - len(suffix); len(base) > room {
		if room <= 0 {
			return ""
		}
		base = base[:room]
	}
	return strings.TrimSuffix(base, "_") + suffix
}

// join concatenates two name fragments with sep, keeping the result inside
// MaxLength by trimming the second fragment, which is the less identifying half.
func join(a, sep, b string) string {
	if a == "" || b == "" {
		return ""
	}
	combined := a + sep + b
	if len(combined) > MaxLength {
		room := MaxLength - len(a) - len(sep)
		if room <= 0 {
			return ""
		}
		combined = a + sep + b[:room]
	}
	return strings.TrimSuffix(combined, "_")
}

// slug coerces raw into the canonical charset without rejecting it.
//
// Disallowed characters are dropped rather than replaced, so "Alex Smith" and
// "Alex.Smith" both yield "alexsmith" instead of a handle carrying a separator
// the user did not choose; the underscore-joined form is offered separately by
// Candidates. Leading non-letters are removed because a canonical handle must
// start with a letter, and a trailing underscore is trimmed for the same reason.
//
// The result is ASCII by construction, which is what makes byte slicing of a
// slug safe elsewhere in this file. It is not guaranteed valid — it may be too
// short, or reserved — so callers pass it through Valid before use.
func slug(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > MaxInputBytes {
		return ""
	}

	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range strings.ToLower(norm.NFKC.String(trimmed)) {
		if isAllowed(r) {
			b.WriteRune(r)
		}
	}

	out := strings.TrimLeft(b.String(), "0123456789_")
	if len(out) > MaxLength {
		out = out[:MaxLength]
	}
	return strings.TrimRight(out, "_")
}

// nameParts splits a display name into slugged fragments, dropping any that
// coerce to nothing. Returns nil for a name with no usable letters.
func nameParts(fullName string) []string {
	trimmed := strings.TrimSpace(fullName)
	if trimmed == "" || len(trimmed) > maxNameInputBytes {
		return nil
	}

	fields := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ' ' || r == '.' || r == '-' || r == '_' || r == ',' || r == '\''
	})

	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		if s := slug(f); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return parts
}
