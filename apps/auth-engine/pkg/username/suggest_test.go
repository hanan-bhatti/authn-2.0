/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/username/suggest_test.go
 * Tier: Shared Package / Identifier Normalization
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package username

import (
	"strings"
	"testing"
)

// TestCandidatesAreAllStorable is the invariant the availability endpoint relies
// on: a suggestion is offered to the user as a handle they can click and keep, so
// one that fails validation would be a dead end presented as a choice.
func TestCandidatesAreAllStorable(t *testing.T) {
	seeds := []struct {
		seed string
		name string
	}{
		{"alexsmith", "Alex Smith"},
		{"Alex Smith", "Alex Smith"},
		{"admin", "Alex Smith"},
		{"a", "Alex Smith"},
		{"@@@@", "Alex Smith"},
		{"1234", "Alex Smith"},
		{strings.Repeat("a", 60), "Alex Smith"},
		{"alex.smith-99", ""},
		{"alexsmith", ""},
	}

	for _, s := range seeds {
		t.Run(s.seed+"/"+s.name, func(t *testing.T) {
			for _, candidate := range Candidates(s.seed, s.name, CandidatePoolSize) {
				if _, err := Canonical(candidate); err != nil {
					t.Fatalf("Candidates(%q, %q) offered %q, which Canonical refuses: %v",
						s.seed, s.name, candidate, err)
				}
			}
		})
	}
}

// TestCandidatesAreDistinct checks the deduplication. A repeated entry wastes a
// slot in a pool sized for the batched availability query and shows the user the
// same alternative twice.
func TestCandidatesAreDistinct(t *testing.T) {
	got := Candidates("alexsmith", "Alex Smith", CandidatePoolSize)
	seen := make(map[string]struct{}, len(got))
	for _, candidate := range got {
		if _, dup := seen[candidate]; dup {
			t.Fatalf("Candidates returned %q twice: %v", candidate, got)
		}
		seen[candidate] = struct{}{}
	}
	if len(got) != CandidatePoolSize {
		t.Fatalf("Candidates filled %d of %d slots for a common stem: %v",
			len(got), CandidatePoolSize, got)
	}
}

// TestCandidatesLeadWithTheSalvagedSeed checks the ordering promise. The first
// entry is the one the user is most likely to accept, so a pool that led with a
// random suffix would bury the useful answer.
func TestCandidatesLeadWithTheSalvagedSeed(t *testing.T) {
	cases := []struct {
		seed string
		want string
	}{
		{"AlexSmith", "alexsmith"},
		{"Alex Smith", "alexsmith"},
		{"alex.smith", "alexsmith"},
		{"  Alex-Smith  ", "alexsmith"},
		{"1alexsmith", "alexsmith"},
	}

	for _, tc := range cases {
		t.Run(tc.seed, func(t *testing.T) {
			got := Candidates(tc.seed, "", CandidatePoolSize)
			if len(got) == 0 {
				t.Fatalf("Candidates(%q, \"\") returned nothing", tc.seed)
			}
			if got[0] != tc.want {
				t.Fatalf("Candidates(%q, \"\")[0] = %q, want %q", tc.seed, got[0], tc.want)
			}
		})
	}
}

// TestCandidatesUseTheName checks that a supplied display name produces the
// deliberate-looking forms before any suffixed one, since "alex_smith" reads as a
// choice where "alexsmith4821" reads as a fallback.
func TestCandidatesUseTheName(t *testing.T) {
	got := Candidates("alexsmith", "Alex Smith", CandidatePoolSize)

	for _, want := range []string{"alex_smith", "asmith", "smith_alex"} {
		if !contains(got, want) {
			t.Fatalf("Candidates did not offer %q for the name %q: %v", want, "Alex Smith", got)
		}
	}

	suffixed := indexOf(got, "alexsmith1")
	named := indexOf(got, "alex_smith")
	if suffixed >= 0 && named >= 0 && named > suffixed {
		t.Fatalf("a suffixed candidate outranked a name-derived one: %v", got)
	}
}

// TestCandidatesRespectTheLengthCeiling covers the truncation path. A seed at the
// ceiling has no room for a suffix, so the base must be trimmed rather than the
// result allowed to overflow.
func TestCandidatesRespectTheLengthCeiling(t *testing.T) {
	long := strings.Repeat("a", MaxLength)
	got := Candidates(long, "", CandidatePoolSize)
	if len(got) < 2 {
		t.Fatalf("a seed at the length ceiling produced %d candidates, want alternatives: %v", len(got), got)
	}
	for _, candidate := range got {
		if len(candidate) > MaxLength {
			t.Fatalf("candidate %q is %d characters, over the %d ceiling", candidate, len(candidate), MaxLength)
		}
	}
}

// TestCandidatesExcludeReservedHandles checks that a seed which slugs onto a
// reserved handle is not offered back. Suggesting "admin" would produce a
// suggestion the write path then refuses.
func TestCandidatesExcludeReservedHandles(t *testing.T) {
	got := Candidates("Admin", "", CandidatePoolSize)
	for _, candidate := range got {
		if Reserved(candidate) {
			t.Fatalf("Candidates offered the reserved handle %q: %v", candidate, got)
		}
	}
	if len(got) == 0 {
		t.Fatal("a reserved seed produced no alternatives at all")
	}
	if got[0] == "admin" {
		t.Fatalf("Candidates led with the reserved seed itself: %v", got)
	}
}

// TestCandidatesReturnNothingWithoutLetters checks the empty case. There is no
// handle to derive from input carrying no letters, and inventing one unrelated to
// what the user typed would be noise rather than a suggestion.
func TestCandidatesReturnNothingWithoutLetters(t *testing.T) {
	for _, seed := range []string{"", "   ", "1234", "!!!!", "____"} {
		if got := Candidates(seed, "", CandidatePoolSize); len(got) != 0 {
			t.Fatalf("Candidates(%q, \"\") = %v, want none", seed, got)
		}
	}
}

// TestCandidatesHonourTheLimit checks that the pool size is a bound and not a
// target, because the caller sizes it to the batched query it is about to run.
func TestCandidatesHonourTheLimit(t *testing.T) {
	for _, n := range []int{0, -1, 1, 2, 5, CandidatePoolSize} {
		if got := Candidates("alexsmith", "Alex Smith", n); len(got) > max(n, 0) {
			t.Fatalf("Candidates(..., %d) returned %d candidates", n, len(got))
		}
	}
}

// TestCandidatesFallBackToTheName checks the path where the seed alone is
// unusable. A user who typed two characters still gets alternatives, built from
// the name they gave at sign-up.
func TestCandidatesFallBackToTheName(t *testing.T) {
	got := Candidates("al", "Alex Smith", CandidatePoolSize)
	if len(got) == 0 {
		t.Fatal("an unusably short seed with a name present produced no candidates")
	}
	if !contains(got, "alex_smith") {
		t.Fatalf("the name was not used as a fallback: %v", got)
	}
}

func contains(haystack []string, needle string) bool {
	return indexOf(haystack, needle) >= 0
}

func indexOf(haystack []string, needle string) int {
	for i, v := range haystack {
		if v == needle {
			return i
		}
	}
	return -1
}
