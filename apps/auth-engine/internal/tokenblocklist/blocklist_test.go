/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/tokenblocklist/blocklist_test.go
 * Tier: Infrastructure / Token Revocation Store Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package tokenblocklist_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/tokenblocklist"
	"github.com/redis/go-redis/v9"
)

// newBlocklist returns a blocklist over an in-process Redis, along with the fake
// server so a test can advance its clock or corrupt a key directly.
func newBlocklist(t *testing.T) (*tokenblocklist.Blocklist, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return tokenblocklist.New(rdb), mr
}

func TestJTIRevocation(t *testing.T) {
	bl, mr := newBlocklist(t)
	ctx := context.Background()

	if bl.IsBlocked(ctx, "jti_never_revoked") {
		t.Fatal("an unrecorded jti reports as blocked")
	}

	bl.Block(ctx, "jti_revoked", 10*time.Minute)
	if !bl.IsBlocked(ctx, "jti_revoked") {
		t.Fatal("a recorded jti does not report as blocked")
	}

	// A zero TTL is the already-expired token: recording it would leave a key with
	// no expiry, which in Redis means forever.
	bl.Block(ctx, "jti_expired", 0)
	if bl.IsBlocked(ctx, "jti_expired") {
		t.Fatal("a zero-TTL block was recorded, leaving a key that never expires")
	}

	// The entry has to release itself. Nothing sweeps this keyspace, so a key that
	// outlives its token would revoke every future token reusing the identifier.
	mr.FastForward(11 * time.Minute)
	if bl.IsBlocked(ctx, "jti_revoked") {
		t.Fatal("the revocation outlived its TTL")
	}
}

// TestCutoffOrdersTokensAgainstTheRestriction is the core of ban enforcement: the
// cutoff has to divide the tokens minted before the restriction from any minted
// after it, with the boundary second falling on the refused side.
func TestCutoffOrdersTokensAgainstTheRestriction(t *testing.T) {
	bl, _ := newBlocklist(t)
	ctx := context.Background()
	const userID = "usr_banned"

	banned := time.Unix(1_700_000_000, 0)
	bl.BlockUserTokensIssuedBefore(ctx, userID, banned, 20*time.Minute)

	if got := bl.UserTokenCutoff(ctx, userID); got != banned.Unix() {
		t.Fatalf("UserTokenCutoff = %d, want %d", got, banned.Unix())
	}

	cases := []struct {
		name    string
		iat     int64
		refused bool
	}{
		{"token from before the ban", banned.Unix() - 300, true},
		{"token from the second before", banned.Unix() - 1, true},
		{"token from the ban's own second", banned.Unix(), true},
		{"token minted a second later", banned.Unix() + 1, false},
		{"token minted long after", banned.Unix() + 3600, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bl.IsUserTokenRefused(ctx, userID, tc.iat); got != tc.refused {
				t.Fatalf("IsUserTokenRefused(iat=%d) = %v, want %v", tc.iat, got, tc.refused)
			}
		})
	}
}

// TestAnUnrestrictedUserIsNeverRefused guards the blast radius. This check runs on
// every authenticated request for every user, so a cutoff bleeding across users —
// or a missing key reading as a restriction — is a platform-wide outage.
func TestAnUnrestrictedUserIsNeverRefused(t *testing.T) {
	bl, _ := newBlocklist(t)
	ctx := context.Background()
	now := time.Now()

	bl.BlockUserTokensIssuedBefore(ctx, "usr_banned", now, 20*time.Minute)

	if bl.IsUserTokenRefused(ctx, "usr_untouched", now.Unix()-60) {
		t.Fatal("another user's cutoff refused an unrestricted user's token")
	}
	if got := bl.UserTokenCutoff(ctx, "usr_untouched"); got != 0 {
		t.Fatalf("UserTokenCutoff for an unrestricted user = %d, want 0", got)
	}
	// An unsigned token carries no iat to compare, and treating a zero as "issued
	// at the epoch" would refuse it against every cutoff ever set.
	if bl.IsUserTokenRefused(ctx, "usr_banned", 0) {
		t.Fatal("a token with no issued-at claim was refused against a cutoff")
	}
	// A negative issued-at is a crafted claim. It has to read as "no restriction"
	// rather than as a restriction on a user who has none, since the caller would
	// otherwise be told their account was banned when it was the token that was
	// malformed — and this path runs for every user, restricted or not.
	if bl.IsUserTokenRefused(ctx, "usr_untouched", -1) {
		t.Fatal("a negative issued-at was treated as a restriction on an unrestricted user")
	}
}

// TestLiftingARestrictionTakesEffectImmediately covers unban. The cutoff carries a
// TTL as its backstop, but an operator reversing a decision cannot be told to wait
// out an access-token lifetime for it.
func TestLiftingARestrictionTakesEffectImmediately(t *testing.T) {
	bl, _ := newBlocklist(t)
	ctx := context.Background()
	const userID = "usr_reinstated"

	banned := time.Now()
	bl.BlockUserTokensIssuedBefore(ctx, userID, banned, 20*time.Minute)
	if !bl.IsUserTokenRefused(ctx, userID, banned.Unix()-10) {
		t.Fatal("setup failed: the cutoff did not refuse an older token")
	}

	bl.ClearUserTokenCutoff(ctx, userID)

	if bl.IsUserTokenRefused(ctx, userID, banned.Unix()-10) {
		t.Fatal("a token is still refused after the restriction was lifted")
	}
	if got := bl.UserTokenCutoff(ctx, userID); got != 0 {
		t.Fatalf("UserTokenCutoff after clearing = %d, want 0", got)
	}
}

// TestCutoffReleasesItself pins the TTL. Once every token the cutoff covered has
// expired on its own it has nothing left to refuse, and the restricted account's
// sessions are already revoked, so a stale key would only cost lookups.
func TestCutoffReleasesItself(t *testing.T) {
	bl, mr := newBlocklist(t)
	ctx := context.Background()
	const userID = "usr_timed_out"

	banned := time.Now()
	bl.BlockUserTokensIssuedBefore(ctx, userID, banned, 15*time.Minute)
	mr.FastForward(16 * time.Minute)

	if got := bl.UserTokenCutoff(ctx, userID); got != 0 {
		t.Fatalf("the cutoff outlived its TTL: got %d, want 0", got)
	}

	// A non-positive TTL is the caller asking for a cutoff with no expiry, which
	// would restrict the account permanently even after it is reinstated.
	bl.BlockUserTokensIssuedBefore(ctx, "usr_no_ttl", banned, 0)
	if got := bl.UserTokenCutoff(ctx, "usr_no_ttl"); got != 0 {
		t.Fatalf("a zero-TTL cutoff was recorded: got %d, want 0", got)
	}
}

// TestFailsOpenOnUnusableState is the availability half of the contract. Both a
// missing Redis and a corrupted value must admit the request: the token still has
// to pass signature and expiry checks, whereas failing closed here would refuse
// every user on the deployment.
func TestFailsOpenOnUnusableState(t *testing.T) {
	ctx := context.Background()

	// The no-Redis configuration. A nil receiver rather than a nil field, because
	// wiring passes a nil *Blocklist when Redis is absent.
	var absent *tokenblocklist.Blocklist
	if absent.IsBlocked(ctx, "jti_anything") {
		t.Error("nil blocklist reported a jti as blocked")
	}
	if absent.IsUserTokenRefused(ctx, "usr_anyone", time.Now().Unix()) {
		t.Error("nil blocklist refused a token")
	}
	if got := absent.UserTokenCutoff(ctx, "usr_anyone"); got != 0 {
		t.Errorf("nil blocklist returned cutoff %d, want 0", got)
	}
	absent.Block(ctx, "jti_anything", time.Minute)
	absent.BlockUserTokensIssuedBefore(ctx, "usr_anyone", time.Now(), time.Minute)
	absent.ClearUserTokenCutoff(ctx, "usr_anyone")

	// An unparseable value: something other than this code wrote the key, or the
	// encoding changed under it. Treated as no cutoff at all.
	bl, mr := newBlocklist(t)
	if err := mr.Set("user_iat_cutoff:usr_corrupt", "not-a-timestamp"); err != nil {
		t.Fatalf("seeding the corrupt key failed: %v", err)
	}
	if got := bl.UserTokenCutoff(ctx, "usr_corrupt"); got != 0 {
		t.Errorf("an unparseable cutoff returned %d, want 0", got)
	}
	if bl.IsUserTokenRefused(ctx, "usr_corrupt", time.Now().Unix()) {
		t.Error("an unparseable cutoff refused a token")
	}

	// An empty user ID reaches here from a token with no subject claim. It must not
	// address the prefix key itself, which every subject-less token would share.
	if bl.IsUserTokenRefused(ctx, "", time.Now().Unix()) {
		t.Error("an empty user ID was matched against a cutoff")
	}

	// A Redis that is reachable but failing. Not distinguishable from a cutoff
	// being absent, and deliberately so.
	mr.Close()
	if bl.IsUserTokenRefused(ctx, "usr_corrupt", time.Now().Unix()) {
		t.Error("an unreachable Redis refused a token instead of failing open")
	}
	if bl.IsBlocked(ctx, "jti_anything") {
		t.Error("an unreachable Redis reported a jti as blocked")
	}
}
