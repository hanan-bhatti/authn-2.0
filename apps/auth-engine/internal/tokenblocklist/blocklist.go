/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/tokenblocklist/blocklist.go
 * Tier: Infrastructure / Token Revocation Store
 *
 * Short-lived JTI revocation store backed by Redis. Each revoked token
 * occupies exactly one key whose TTL matches the token's own remaining
 * lifetime, so the key expires on its own when the token would have anyway —
 * no background sweeper required.
 *
 * Alongside single-token revocation it holds a per-user issued-at cutoff, which
 * is how a restriction placed on an account takes effect before the tokens
 * already in circulation expire. Revoking one token needs its identifier;
 * banning an account does not have that identifier for any of the tokens it
 * handed out, so the two need different shapes.
 *
 * A nil Blocklist (e.g. Redis is unconfigured) is explicitly safe and makes
 * every call a no-op. The check path also fails open: a Redis error is logged
 * but does not block the request, since RequireClientAuth downstream enforces
 * signature and expiry regardless.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package tokenblocklist

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const keyPrefix = "jti_block:"

// userCutoffPrefix namespaces the per-user issued-at cutoffs. Kept distinct from
// keyPrefix so a user ID can never collide with a token identifier.
const userCutoffPrefix = "user_iat_cutoff:"

// Blocklist is a Redis-backed revocation store for JWT token identifiers.
type Blocklist struct {
	rdb *redis.Client
}

// New returns a Blocklist backed by rdb. Passing nil produces a no-op blocklist.
func New(rdb *redis.Client) *Blocklist {
	return &Blocklist{rdb: rdb}
}

// Block records jti as revoked for ttl. If ttl is zero or negative the call is
// skipped — there is no point blocking a token that is already expired.
func (b *Blocklist) Block(ctx context.Context, jti string, ttl time.Duration) {
	if b == nil || b.rdb == nil || ttl <= 0 {
		return
	}
	if err := b.rdb.SetEx(ctx, keyPrefix+jti, "1", ttl).Err(); err != nil {
		log.Printf("[warn] tokenblocklist: failed to record jti=%s: %v", jti, err)
	}
}

// IsBlocked reports whether jti is on the revocation list. It fails open on
// any Redis error, logging the failure.
func (b *Blocklist) IsBlocked(ctx context.Context, jti string) bool {
	if b == nil || b.rdb == nil {
		return false
	}
	exists, err := b.rdb.Exists(ctx, keyPrefix+jti).Result()
	if err != nil {
		log.Printf("[warn] tokenblocklist: blocklist check failed for jti=%s: %v", jti, err)
		return false
	}
	return exists > 0
}

// BlockUserTokensIssuedBefore refuses every access token for userID that was
// issued at or before cutoff, for ttl.
//
// This is what makes a ban or a suspension take hold now rather than whenever
// the last outstanding access token happens to expire. Per-JTI revocation cannot
// express it: the identifiers of the tokens a user is currently holding are not
// recorded anywhere, and recording them would mean a write on every sign-in to
// serve an action that almost never happens.
//
// ttl should be the access-token lifetime plus a margin for clock skew. Past
// that point the cutoff has nothing left to refuse — every token it covered has
// expired on its own — and the account's sessions were revoked alongside the
// restriction, so no new token can be minted for it either.
func (b *Blocklist) BlockUserTokensIssuedBefore(ctx context.Context, userID string, cutoff time.Time, ttl time.Duration) {
	if b == nil || b.rdb == nil || userID == "" || ttl <= 0 {
		return
	}
	val := strconv.FormatInt(cutoff.Unix(), 10)
	if err := b.rdb.SetEx(ctx, userCutoffPrefix+userID, val, ttl).Err(); err != nil {
		log.Printf("[warn] tokenblocklist: failed to record issued-at cutoff for user=%s: %v", userID, err)
	}
}

// UserTokenCutoff returns the issued-at cutoff recorded for userID as a Unix
// timestamp, or 0 when none is recorded.
//
// Fails open, returning 0 on any Redis error, for the same reason IsBlocked
// does: a Redis outage must not lock every user out of a platform whose tokens
// are still individually valid. The cost of failing open is bounded — one
// access-token lifetime, after which refresh is refused from the database.
func (b *Blocklist) UserTokenCutoff(ctx context.Context, userID string) int64 {
	if b == nil || b.rdb == nil || userID == "" {
		return 0
	}
	val, err := b.rdb.Get(ctx, userCutoffPrefix+userID).Result()
	if err != nil {
		if err != redis.Nil {
			log.Printf("[warn] tokenblocklist: issued-at cutoff check failed for user=%s: %v", userID, err)
		}
		return 0
	}
	cutoff, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		log.Printf("[warn] tokenblocklist: unparseable issued-at cutoff for user=%s: %q", userID, val)
		return 0
	}
	return cutoff
}

// ClearUserTokenCutoff drops the cutoff for userID, which is what lets a lifted
// restriction take effect immediately rather than waiting out the TTL.
func (b *Blocklist) ClearUserTokenCutoff(ctx context.Context, userID string) {
	if b == nil || b.rdb == nil || userID == "" {
		return
	}
	if err := b.rdb.Del(ctx, userCutoffPrefix+userID).Err(); err != nil {
		log.Printf("[warn] tokenblocklist: failed to clear issued-at cutoff for user=%s: %v", userID, err)
	}
}

// IsUserTokenRefused reports whether a token for userID issued at iat (a Unix
// timestamp) falls at or before the recorded cutoff.
//
// The boundary second is refused rather than admitted. A token issued in the
// same second as the restriction cannot be ordered against it from second
// precision alone, and the account it belongs to has no legitimate reason to be
// minting tokens at that moment: its sessions were revoked by the same action
// that set the cutoff.
func (b *Blocklist) IsUserTokenRefused(ctx context.Context, userID string, iat int64) bool {
	if b == nil || b.rdb == nil || userID == "" || iat == 0 {
		return false
	}
	cutoff := b.UserTokenCutoff(ctx, userID)
	return cutoff > 0 && iat <= cutoff
}
