/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/service.go
 * Tier: Internal Feature Package / API Key Business Logic
 *
 * Description: Business logic for API key generation, HMAC-SHA256 peppered hash validation,
 *              expiration & revocation checks, and application/tenant resolution.
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
)

var (
	ErrInvalidApiKey   = errors.New("invalid or unrecognized API key")
	ErrExpiredApiKey   = errors.New("API key has expired")
	ErrRevokedApiKey   = errors.New("API key has been revoked")
	ErrKeyTypeMismatch = errors.New("API key scope type mismatch")
)

// Service provides business logic operations for API Key management and validation.
type Service struct {
	repo   *Repository
	pepper string
}

// NewService constructs a new API Key Service instance.
func NewService(repo *Repository, pepper string) *Service {
	return &Service{
		repo:   repo,
		pepper: pepper,
	}
}

// ComputeHash returns the peppered HMAC-SHA256 hash string for a raw key.
func (s *Service) ComputeHash(rawKey string) string {
	h := hmac.New(sha256.New, []byte(s.pepper))
	h.Write([]byte(rawKey))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateKey checks a raw API key string against database records and returns key & application entity metadata.
func (s *Service) ValidateKey(ctx context.Context, rawKey string, expectedType KeyType) (*ent.ApiKey, *ent.Application, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil, nil, ErrInvalidApiKey
	}

	keyHash := s.ComputeHash(rawKey)

	// Execute key lookup using system bypass context
	sysCtx := privacy.NewBypassContext(ctx)
	key, err := s.repo.FindByHash(sysCtx, keyHash)
	if err != nil || key == nil {
		return nil, nil, ErrInvalidApiKey
	}

	if key.RevokedAt != nil {
		return nil, nil, ErrRevokedApiKey
	}

	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return nil, nil, ErrExpiredApiKey
	}

	if expectedType != "" && KeyType(key.Type) != expectedType {
		return nil, nil, ErrKeyTypeMismatch
	}

	// Fetch parent Application to resolve tenant_id and environment
	app, err := s.repo.factory.GetClient(sysCtx, "", "").Application.Query().
		Where(application.ID(key.ApplicationID)).
		Only(sysCtx)
	if err != nil || app == nil {
		return nil, nil, fmt.Errorf("parent application for API key not found")
	}

	return key, app, nil
}

// CreateKey generates and persists a new API key for an application.
func (s *Service) CreateKey(ctx context.Context, id string, applicationID string, name string, keyType KeyType, env string, expiresAt *time.Time) (*GeneratedApiKey, error) {
	gen, err := GenerateApiKey(keyType, env, s.pepper)
	if err != nil {
		return nil, err
	}

	if id == "" {
		id = fmt.Sprintf("key_%s", gen.RawKey[len(gen.RawKey)-12:])
	}

	_, err = s.repo.CreateApiKey(ctx, id, applicationID, name, keyType, gen.Prefix, gen.KeyHash, env, expiresAt)
	if err != nil {
		return nil, err
	}

	gen.ID = id
	return gen, nil
}

// ListKeys returns all API keys for an application.
func (s *Service) ListKeys(ctx context.Context, applicationID string) ([]*ent.ApiKey, error) {
	return s.repo.ListByApplication(ctx, applicationID)
}

// RevokeKey soft-revokes an API key by ID.
func (s *Service) RevokeKey(ctx context.Context, id string) error {
	return s.repo.RevokeApiKey(ctx, id)
}
