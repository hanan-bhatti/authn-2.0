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
	"time"

	"github.com/redis/go-redis/v9"
)

const keyPrefix = "jti_block:"

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
