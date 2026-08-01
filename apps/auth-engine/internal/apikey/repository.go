/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/repository.go
 * Tier: Internal Feature Package / API Key Repository
 *
 * Description: Data access layer for API Key CRUD operations.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package apikey

import (
	"context"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// Repository handles database operations for API Key entities.
type Repository struct {
	factory *clientfactory.ClientFactory
}

// NewRepository creates a new API Key repository.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// CreateApiKey persists a new API key record into the database.
func (r *Repository) CreateApiKey(ctx context.Context, id string, applicationID string, name string, keyType KeyType, prefix string, keyHash string, env string, expiresAt *time.Time) (*ent.ApiKey, error) {
	client := r.factory.GetClient(ctx, "", env)
	k, err := client.ApiKey.Create().
		SetID(id).
		SetApplicationID(applicationID).
		SetNillableName(&name).
		SetType(apikey.Type(keyType)).
		SetKeyPrefix(prefix).
		SetKeyHash(keyHash).
		SetEnvironment(apikey.Environment(env)).
		SetNillableExpiresAt(expiresAt).
		Save(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed creating api key: %w", err)
	}
	return k, nil
}

// FindByHash queries an API key by its peppered hash.
func (r *Repository) FindByHash(ctx context.Context, keyHash string) (*ent.ApiKey, error) {
	client := r.factory.GetClient(ctx, "", "")
	k, err := client.ApiKey.Query().
		Where(apikey.KeyHash(keyHash)).
		Only(ctx)

	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed querying api key by hash: %w", err)
	}
	return k, nil
}

// ListByApplication lists all API keys for an application.
func (r *Repository) ListByApplication(ctx context.Context, applicationID string) ([]*ent.ApiKey, error) {
	client := r.factory.GetClient(ctx, "", "")
	keys, err := client.ApiKey.Query().
		Where(apikey.ApplicationID(applicationID)).
		All(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed listing api keys: %w", err)
	}
	return keys, nil
}

// RevokeApiKey marks an API key as revoked.
func (r *Repository) RevokeApiKey(ctx context.Context, id string) error {
	client := r.factory.GetClient(ctx, "", "")
	now := time.Now()
	_, err := client.ApiKey.UpdateOneID(id).
		SetRevokedAt(now).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed revoking api key %s: %w", id, err)
	}
	return nil
}
