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
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/database"
)

// PoolOptions tunes the underlying database connection pool.
//
// Defaults apply to any field left at zero, so a caller may set only the
// values it cares about.
type PoolOptions struct {
	// MaxOpenConns caps total simultaneous connections. Keep the sum across all
	// running instances below the database server's own connection limit.
	MaxOpenConns int
	// MaxIdleConns caps connections held open for reuse. Too low and the pool
	// reconnects constantly under steady load.
	MaxIdleConns int
	// ConnMaxLifetime retires a connection after this age so instances notice
	// failovers and DNS changes instead of holding a dead socket.
	ConnMaxLifetime time.Duration
	// AutoMigrate creates or updates schema tables at startup.
	AutoMigrate bool
}

// ClientFactory manages Ent ORM database connection pools for tenants and environments.
type ClientFactory struct {
	mu            sync.RWMutex
	defaultClient *ent.Client
	pools         map[string]*ent.Client
}

// NewFromURL opens a connection pool using the engine implied by databaseURL's
// scheme, so the URL alone decides whether this is PostgreSQL, MySQL or SQLite.
//
// Returns an error when the scheme names an unsupported engine, when the
// connection cannot be opened, or when AutoMigrate is set and schema creation
// fails. Each is a startup failure.
func NewFromURL(databaseURL string, opts PoolOptions) (*ClientFactory, error) {
	driver, dsn, err := database.Resolve(databaseURL)
	if err != nil {
		return nil, err
	}

	pool, err := entsql.Open(driver.Dialect, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s database: %w", driver.Dialect, err)
	}

	db := pool.DB()
	if opts.MaxOpenConns > 0 {
		db.SetMaxOpenConns(opts.MaxOpenConns)
	}
	if opts.MaxIdleConns > 0 {
		db.SetMaxIdleConns(opts.MaxIdleConns)
	}
	if opts.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(opts.ConnMaxLifetime)
	}

	client := ent.NewClient(ent.Driver(pool))

	if opts.AutoMigrate {
		if err := client.Schema.Create(context.Background()); err != nil {
			client.Close()
			return nil, fmt.Errorf("creating %s schema: %w", driver.Dialect, err)
		}
	}

	return &ClientFactory{
		defaultClient: client,
		pools:         make(map[string]*ent.Client),
	}, nil
}

// NewClientFactory opens a pool against an explicit driver name and connection
// string, always running schema migration.
//
// Prefer NewFromURL in application code, where the engine should follow from
// configuration. This form exists for tests, which want a specific in-memory
// SQLite database rather than whatever the environment points at.
//
// Returns an error if the connection cannot be opened or the schema cannot be
// created.
func NewClientFactory(driverName string, dataSourceName string) (*ClientFactory, error) {
	client, err := ent.Open(driverName, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed opening connection to %s: %w", driverName, err)
	}

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

// Ping checks database connectivity on default client with context timeout.
func (f *ClientFactory) Ping(ctx context.Context) error {
	if f == nil || f.defaultClient == nil {
		return fmt.Errorf("database client uninitialized")
	}
	_, err := f.defaultClient.Tenant.Query().Limit(1).IDs(ctx)
	return err
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
