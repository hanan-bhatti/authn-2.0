/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/clientfactory/client_factory.go
 * Tier: Shared Package / Ent Connection Pooling
 *
 * Description: ClientFactory abstraction for Ent ORM connection pool management.
 *              Provides logical environment multi-tenancy by default and supports
 *              physical DB connection pool routing for Enterprise self-hosters.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package clientfactory

import (
	"context"
	"fmt"
	"sync"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// ClientFactory manages Ent ORM database connection pools for tenants and environments.
type ClientFactory struct {
	mu            sync.RWMutex
	defaultClient *ent.Client
	pools         map[string]*ent.Client
}

// NewClientFactory initializes a new ClientFactory with a default database connection.
//
// Parameters:
//   - driverName: SQL driver name ("postgres", "sqlite3", "mysql").
//   - dataSourceName: SQL connection string.
//
// Returns:
//   - *ClientFactory: Initialized factory instance.
//   - error: Non-nil if initial DB connection fails.
func NewClientFactory(driverName string, dataSourceName string) (*ClientFactory, error) {
	client, err := ent.Open(driverName, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed opening connection to %s: %w", driverName, err)
	}

	// Auto-migrate schema tables
	if err := client.Schema.Create(context.Background()); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed creating schema resources: %w", err)
	}

	return &ClientFactory{
		defaultClient: client,
		pools:         make(map[string]*ent.Client),
	}, nil
}

// GetClient returns the Ent client instance for a given tenant and environment.
//
// Parameters:
//   - ctx: Request context.
//   - tenantID: Unique Tenant ID.
//   - environment: Environment mode ("test" or "live").
//
// Returns:
//   - *ent.Client: Active Ent database client.
func (f *ClientFactory) GetClient(ctx context.Context, tenantID string, environment string) *ent.Client {
	poolKey := fmt.Sprintf("%s:%s", tenantID, environment)

	f.mu.RLock()
	if poolClient, exists := f.pools[poolKey]; exists {
		f.mu.RUnlock()
		return poolClient
	}
	f.mu.RUnlock()

	return f.defaultClient
}

// Close gracefully closes all active database connection pools.
//
// Parameters: None
//
// Returns:
//   - error: Combined error if any pool fails to close.
func (f *ClientFactory) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var errs []error
	if err := f.defaultClient.Close(); err != nil {
		errs = append(errs, err)
	}

	for key, client := range f.pools {
		if err := client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed closing pool %s: %w", key, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing client factory pools: %v", errs)
	}
	return nil
}
