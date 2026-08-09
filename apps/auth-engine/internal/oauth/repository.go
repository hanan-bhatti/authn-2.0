/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/repository.go
 * Tier: Internal Feature Package / OAuth2 Repository
 *
 * Description: Storage for in-flight OAuth2 authorization codes. Codes live
 *              only between the authorization request and the token exchange,
 *              so they are held in process memory rather than the database.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Repository holds authorization codes for the seconds between issue and
// redemption.
//
// State is per-process. A deployment running several instances must therefore
// route the authorization request and the matching token exchange to the same
// instance, or codes issued by one will not be redeemable at another.
type Repository struct {
	// mu guards codes against concurrent requests.
	mu sync.RWMutex
	// codes maps a code string to the request it was issued for.
	codes map[string]AuthorizationCode
}

// NewRepository constructs an empty Repository.
func NewRepository() *Repository {
	return &Repository{
		codes: make(map[string]AuthorizationCode),
	}
}

// SaveAuthorizationCode stores code until it is consumed or expires.
//
// Returns an error if the code string is empty.
func (r *Repository) SaveAuthorizationCode(ctx context.Context, code AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if code.Code == "" {
		return fmt.Errorf("authorization code string cannot be empty")
	}

	r.purgeExpiredLocked()

	r.codes[code.Code] = code
	return nil
}

// purgeExpiredLocked drops every code past its expiry. The caller must hold mu.
//
// An abandoned flow — the user closes the tab after authorizing — leaves a code
// that is never consumed and so never deleted on the redemption path. Sweeping
// on write bounds the map by the number of codes issued within one TTL rather
// than by the uptime of the process.
func (r *Repository) purgeExpiredLocked() {
	now := time.Now()
	for key, code := range r.codes {
		if now.After(code.ExpiresAt) {
			delete(r.codes, key)
		}
	}
}

// ConsumeAuthorizationCode returns the code identified by codeStr and removes
// it from storage.
//
// Removal happens before the expiry check, so a code is spent by the first
// attempt to redeem it whatever the outcome. RFC 6749 section 4.1.2 requires
// single use: a code that survived a failed redemption could be replayed by
// anyone who captured it from the redirect.
//
// Returns an error if the code is unknown, already consumed, or expired.
func (r *Repository) ConsumeAuthorizationCode(ctx context.Context, codeStr string) (*AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	code, exists := r.codes[codeStr]
	if !exists {
		return nil, fmt.Errorf("invalid or expired authorization code")
	}

	delete(r.codes, codeStr)

	if time.Now().After(code.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}

	return &code, nil
}
