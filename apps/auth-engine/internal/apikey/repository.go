/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/apikey/repository.go
 * Tier: Internal Feature Package / API Key Data Access
 *
 * Database access for API key records.
 *
 * Records hold the peppered hash, never the key. A read of this table therefore
 * yields nothing usable as a credential, which is what lets key metadata be
 * listed freely to an application's operators.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package apikey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// seedKeyName labels the key created by EnsureDefaultApiKeyExists, so it is
// distinguishable from an operator-issued one in a listing.
const seedKeyName = "Default Dev Key"

// Repository reads and writes API key records.
type Repository struct {
	// factory supplies the database client for a tenant and environment.
	factory *clientfactory.ClientFactory
}

// NewRepository constructs a repository over the given client factory.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// CreateApiKey persists a key record.
//
// keyHash is the peppered digest; the key itself is never passed here. A nil
// expiresAt stores no expiry, meaning the key is valid until revoked.
//
// Returns an error if the insert fails, which for a duplicate id or a missing
// application is a constraint violation.
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

// FindByHash looks a key up by its peppered hash.
//
// Returns (nil, nil) when no key matches. "Not found" is the ordinary outcome
// for a bad credential, not a failure, and separating it from a real error lets
// the caller answer "invalid key" without treating a database outage the same
// way.
//
// Returns an error only when the query itself fails.
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

// ListByApplication returns every key belonging to an application, revoked and
// expired ones included, so the listing reflects what was issued rather than
// only what currently works.
//
// Returns an error if the query fails.
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

// RevokeApiKey stamps a key's revocation time, confined to tenantID.
//
// The record is retained rather than deleted, keeping the key in the audit
// trail and preventing its identifier from being reused.
//
// The tenant predicate is written here rather than left to the privacy
// interceptor, which cannot supply it: the interceptor wraps Querier, so it
// scopes reads only, and every write predicate in this codebase must therefore
// be explicit. api_keys carries no tenant_id of its own, so the boundary is
// reached through the owning application — the same join the read path applies.
// Without it an UpdateOneID would revoke by bare identifier and let any
// authenticated admin disable another tenant's key.
//
// Returns an error when no key in tenantID has that id, or when the update
// fails. Callers must not distinguish the two for the client, since doing so
// would confirm which identifiers exist in other tenants.
func (r *Repository) RevokeApiKey(ctx context.Context, id string, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("refusing to revoke api key %s: no tenant scope", id)
	}

	client := r.factory.GetClient(ctx, tenantID, "")
	now := time.Now()
	n, err := client.ApiKey.Update().
		Where(
			apikey.ID(id),
			apikey.HasApplicationWith(application.TenantID(tenantID)),
		).
		SetRevokedAt(now).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("failed revoking api key %s: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("no api key %s in tenant %s", id, tenantID)
	}
	return nil
}

// ApplicationInTenant reports whether applicationID names an application owned
// by tenantID.
//
// It exists so a handler can accept an application identifier from the request
// — which the console must supply, holding a tenant-wide credential rather than
// an application-bound one — without trusting it. The tenant predicate is what
// stops a caller naming another tenant's application and issuing keys against
// it.
//
// Returns false with no error when the application does not exist or belongs to
// another tenant; the two are deliberately indistinguishable to the caller.
func (r *Repository) ApplicationInTenant(ctx context.Context, applicationID string, tenantID string) (bool, error) {
	if applicationID == "" || tenantID == "" {
		return false, nil
	}

	client := r.factory.GetClient(ctx, tenantID, "")
	exists, err := client.Application.Query().
		Where(
			application.ID(applicationID),
			application.TenantID(tenantID),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("failed checking application %s in tenant %s: %w", applicationID, tenantID, err)
	}
	return exists, nil
}

// EnsureDefaultApiKeyExists creates a known development key if it is not
// already present, so a freshly seeded database can be exercised without first
// issuing one through the API.
//
// The key type and prefix are inferred from rawKey, letting a caller seed
// either a publishable or a secret key by choosing the value's shape.
//
// Existing keys are left untouched, and a constraint violation is treated as
// success: two processes seeding concurrently both intend the same record, and
// whichever loses the race has still achieved what it asked for.
//
// Returns an error if the existence check fails, or if creation fails for any
// reason other than that conflict.
func (r *Repository) EnsureDefaultApiKeyExists(ctx context.Context, keyID string, appID string, rawKey string, pepper string) error {
	h := hmac.New(sha256.New, []byte(pepper))
	h.Write([]byte(rawKey))
	keyHash := hex.EncodeToString(h.Sum(nil))

	client := r.factory.GetClient(ctx, "", "")
	exists, err := client.ApiKey.Query().Where(apikey.ID(keyID)).Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed checking default api key: %w", err)
	}
	if !exists {
		// Default to the least privileged shape, and widen only on an explicit
		// prefix match, so an unrecognised value seeds a test publishable key
		// rather than a live secret one.
		//
		// The environment follows the same match as the type. The middleware
		// resolves a request's environment from this column, so a row whose prefix
		// reads live while its column reads test would address test data behind a
		// credential an operator reads as live.
		keyType := apikey.TypePublishable
		prefix := "pk_test_"
		env := apikey.EnvironmentTest
		if strings.HasPrefix(rawKey, "sk_test_") {
			keyType = apikey.TypeSecret
			prefix = "sk_test_"
		} else if strings.HasPrefix(rawKey, "sk_live_") {
			keyType = apikey.TypeSecret
			prefix = "sk_live_"
			env = apikey.EnvironmentLive
		} else if strings.HasPrefix(rawKey, "pk_live_") {
			prefix = "pk_live_"
			env = apikey.EnvironmentLive
		}

		_, err := client.ApiKey.Create().
			SetID(keyID).
			SetApplicationID(appID).
			SetName(seedKeyName).
			SetType(keyType).
			SetKeyPrefix(prefix).
			SetKeyHash(keyHash).
			SetEnvironment(env).
			Save(ctx)
		if err != nil && !ent.IsConstraintError(err) {
			return fmt.Errorf("failed auto-creating default api key: %w", err)
		}
	}
	return nil
}
