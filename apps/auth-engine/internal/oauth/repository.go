/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/repository.go
 * Tier: Internal Feature Package / OAuth2 Repository
 *
 * Description: Data access layer for ephemeral OAuth2 authorization codes
 *              and client application validation.
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

// Repository manages ephemeral authorization codes in memory with thread safety.
type Repository struct {
	mu    sync.RWMutex
	codes map[string]AuthorizationCode
}

// NewRepository constructs a new OAuth2 Repository instance.
func NewRepository() *Repository {
	return &Repository{
		codes: make(map[string]AuthorizationCode),
	}
}

// SaveAuthorizationCode stores an authorization code expiring in 10 minutes.
func (r *Repository) SaveAuthorizationCode(ctx context.Context, code AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if code.Code == "" {
		return fmt.Errorf("authorization code string cannot be empty")
	}

	r.codes[code.Code] = code
	return nil
}

// ConsumeAuthorizationCode retrieves and consumes (deletes) an authorization code to prevent reuse attacks (RFC 6749 Section 4.1.2).
func (r *Repository) ConsumeAuthorizationCode(ctx context.Context, codeStr string) (*AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	code, exists := r.codes[codeStr]
	if !exists {
		return nil, fmt.Errorf("invalid or expired authorization code")
	}

	// Single-use guarantee: Delete immediately upon retrieval
	delete(r.codes, codeStr)

	if time.Now().After(code.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}

	return &code, nil
}
