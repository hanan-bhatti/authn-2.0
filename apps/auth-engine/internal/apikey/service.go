/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/service.go
 * Tier: Internal Feature Package / API Key Business Logic
 *
 * Issues, validates and revokes API keys.
 *
 * Validation is on the hot path: middleware calls it for every request that
 * authenticates with a key, and it is what resolves an opaque credential into
 * the tenant and environment the rest of the request is scoped by. Everything
 * downstream trusts the application this returns, so a mistake here is a
 * cross-tenant one.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package apikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

var (
	// ErrInvalidApiKey means the key is empty or matches no stored hash. It is
	// deliberately also returned when the lookup itself fails, so a caller
	// cannot tell a wrong key from a database problem.
	ErrInvalidApiKey = errors.New("invalid or unrecognized API key")
	// ErrExpiredApiKey means the key was valid but has passed its expiry.
	ErrExpiredApiKey = errors.New("API key has expired")
	// ErrRevokedApiKey means the key was explicitly revoked.
	ErrRevokedApiKey = errors.New("API key has been revoked")
	// ErrKeyTypeMismatch means a real key was presented where its scope does
	// not apply — a publishable key at an endpoint requiring a secret one.
	ErrKeyTypeMismatch = errors.New("API key scope type mismatch")
)

// Service issues and validates API keys.
type Service struct {
	// repo reads and writes key records.
	repo *Repository
	// pepper is the HMAC key mixed into every hash. It is held in memory only
	// and never written alongside the hashes it protects.
	pepper string
}

// NewService constructs a key service bound to a repository and pepper.
//
// The pepper must stay stable for the life of the deployment: it is an input to
// every stored hash, so changing it invalidates every key already issued.
func NewService(repo *Repository, pepper string) *Service {
	return &Service{
		repo:   repo,
		pepper: pepper,
	}
}

// ComputeHash derives the stored hash for a raw key.
//
// Exported so middleware can look a key up without going through full
// validation.
func (s *Service) ComputeHash(rawKey string) string {
	h := hmac.New(sha256.New, []byte(s.pepper))
	h.Write([]byte(rawKey))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateKey resolves a raw API key into its key record and owning
// application.
//
// expectedType constrains the scope; passing an empty type accepts either,
// which suits an endpoint that serves both public and administrative clients.
//
// Returns ErrInvalidApiKey for an empty or unrecognised key, ErrRevokedApiKey
// or ErrExpiredApiKey for a key that is known but no longer usable, and
// ErrKeyTypeMismatch when the scope is wrong. Callers should collapse the first
// three into one client-facing response: distinguishing "unknown" from
// "revoked" confirms to an attacker that a key they hold was once real.
//
// The returned application carries the tenant and environment the request is
// then scoped by, so a caller must use those rather than any tenant identifier
// supplied in the request itself.
func (s *Service) ValidateKey(ctx context.Context, rawKey string, expectedType KeyType) (*ent.ApiKey, *ent.Application, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, nil, ErrInvalidApiKey
	}

	keyHash := s.ComputeHash(rawKey)

	// The lookup runs with privacy checks bypassed because it is what
	// establishes tenancy: the interceptors demand a tenant in context, and the
	// tenant is not known until this key resolves. The bypass is confined to
	// this resolution and does not extend to the request that follows.
	sysCtx := privacy.NewBypassContext(ctx)
	key, err := s.repo.FindByHash(sysCtx, keyHash)
	if err != nil || key == nil {
		return nil, nil, ErrInvalidApiKey
	}

	// Revocation is checked before expiry so a key that was revoked and has
	// since also expired reports the deliberate action rather than the passive
	// one.
	if key.RevokedAt != nil {
		return nil, nil, ErrRevokedApiKey
	}

	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return nil, nil, ErrExpiredApiKey
	}

	if expectedType != "" && KeyType(key.Type) != expectedType {
		return nil, nil, ErrKeyTypeMismatch
	}

	// The parent application supplies the tenant and environment. A key whose
	// application has been deleted is unusable, hence the error rather than a
	// partial result.
	app, err := s.repo.factory.GetClient(sysCtx, "", "").Application.Query().
		Where(application.ID(key.ApplicationID)).
		Only(sysCtx)
	if err != nil || app == nil {
		return nil, nil, fmt.Errorf("parent application for API key not found")
	}

	return key, app, nil
}

// CreateKey generates a key for an application and persists its hash.
//
// An empty id is filled with a freshly drawn random value. It is deliberately
// not derived from the generated key: an identifier appears in listings, logs
// and revocation URLs, so seeding it from the secret would publish part of the
// secret everywhere the identifier travels.
//
// A nil expiresAt means the key does not expire. Returns the generated key —
// the only time its raw value is available — or an error if generation or
// persistence fails.
func (s *Service) CreateKey(ctx context.Context, id string, applicationID string, name string, keyType KeyType, env string, expiresAt *time.Time) (*GeneratedApiKey, error) {
	gen, err := GenerateApiKey(keyType, env, s.pepper)
	if err != nil {
		return nil, err
	}

	if id == "" {
		id = idgen.New("key")
	}

	_, err = s.repo.CreateApiKey(ctx, id, applicationID, name, keyType, gen.Prefix, gen.KeyHash, env, expiresAt)
	if err != nil {
		return nil, err
	}

	gen.ID = id
	return gen, nil
}

// ApplicationInTenant reports whether applicationID belongs to tenantID.
//
// Handlers call it before acting on a caller-supplied application identifier,
// so that a tenant-wide credential cannot reach across the tenant boundary by
// naming someone else's application.
//
// Returns false with no error when the application is absent or foreign.
func (s *Service) ApplicationInTenant(ctx context.Context, applicationID string, tenantID string) (bool, error) {
	return s.repo.ApplicationInTenant(ctx, applicationID, tenantID)
}

// ListKeys returns an application's keys, including revoked and expired ones so
// an operator can audit what was issued. Records carry hashes, never keys.
//
// Returns an error if the query fails.
func (s *Service) ListKeys(ctx context.Context, applicationID string) ([]*ent.ApiKey, error) {
	return s.repo.ListByApplication(ctx, applicationID)
}

// RevokeKey marks a key unusable, effective on its next validation.
//
// tenantID confines the revocation to the caller's own tenant; it is required,
// and a key belonging to any other tenant is reported as not found.
//
// The record is kept rather than deleted, so the key remains in the audit trail
// and its identifier cannot be reissued. Returns an error if the key does not
// exist within tenantID or the update fails.
func (s *Service) RevokeKey(ctx context.Context, id string, tenantID string) error {
	return s.repo.RevokeApiKey(ctx, id, tenantID)
}
