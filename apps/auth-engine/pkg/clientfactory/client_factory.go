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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/quota"
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
	// TestLimits bounds how much data a tenant may hold in the test environment.
	// A zero value bounds nothing, which is what a caller that has no opinion
	// should get; the loader fills it from configuration.
	TestLimits quota.Limits
}

// ClientFactory hands out the Ent client a request should use.
//
// Every caller currently receives the same client: the per-tenant pool map is
// read on each lookup but nothing registers an entry, so the tenantID and
// environment arguments to GetClient select nothing today. They are the seam a
// self-hoster would use to route one tenant at its own database, and callers
// pass their real values so that becoming true later requires no change at the
// call sites.
//
// Tenant and environment isolation does NOT come from this type. It is enforced
// by the privacy interceptors, which narrow every query by the tenant and
// environment on the request context. Adding a dedicated pool would be a
// performance and blast-radius choice, not the thing that keeps one tenant's
// rows away from another.
type ClientFactory struct {
	// mu guards pools against concurrent lookup and registration.
	mu sync.RWMutex
	// defaultClient serves every tenant, and is the only client in use unless a
	// dedicated pool has been registered.
	defaultClient *ent.Client
	// pools holds dedicated clients keyed by "tenantID:environment". Nothing
	// populates it yet; see the type comment.
	pools map[string]*ent.Client
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
		// Migration runs before the interceptors are installed, so the DDL is not
		// subject to a tenant scope it could never satisfy.
		if err := client.Schema.Create(context.Background()); err != nil {
			client.Close()
			return nil, fmt.Errorf("creating %s schema: %w", driver.Dialect, err)
		}
	}

	privacy.AttachPrivacyInterceptors(client)
	// After the privacy interceptors, so the counting query behind a ceiling is
	// narrowed to the caller's tenant and environment by the same rules everything
	// else is read under.
	quota.AttachHook(client, opts.TestLimits)

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

	privacy.AttachPrivacyInterceptors(client)

	return &ClientFactory{
		defaultClient: client,
		pools:         make(map[string]*ent.Client),
	}, nil
}

// ApplyTestLimits installs test-environment ceilings on every pool this factory
// holds.
//
// NewFromURL takes them in its options, which is how the server configures them.
// This exists for the callers that open a factory before they have configuration
// to hand it — chiefly the test harness, which opens an in-memory database and
// then decides what each suite should be bounded by.
//
// Calling it twice stacks two hooks, so a caller that means to change a ceiling
// should build a new factory rather than reapply.
func (f *ClientFactory) ApplyTestLimits(limits quota.Limits) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	quota.AttachHook(f.defaultClient, limits)
	for _, poolClient := range f.pools {
		quota.AttachHook(poolClient, limits)
	}
}

// GetClient returns the Ent client serving a tenant and environment, falling
// back to the shared default pool when the pair has no dedicated one.
//
// It never returns nil for a configured factory, so callers do not branch on
// the result. Tenant isolation does not come from this choice: the default pool
// is shared, and it is the privacy interceptors that confine a query to its
// tenant. Passing empty strings selects the default pool explicitly.
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

// Ping reports whether the default pool can serve queries, by running the
// cheapest real query against it.
//
// It issues a bounded query rather than a driver-level ping so that a pool
// which connects but cannot read — a failed-over replica, a revoked grant, a
// missing schema — is reported as unhealthy rather than healthy. Returns an
// error when the factory is uninitialised or the query fails.
func (f *ClientFactory) Ping(ctx context.Context) error {
	if f == nil || f.defaultClient == nil {
		return fmt.Errorf("database client uninitialized")
	}
	// A health probe belongs to no tenant, so it runs under a bypass context.
	// Without one the privacy interceptor refuses the query for want of a scope
	// and readiness fails permanently — every instance would leave the load
	// balancer while the database was perfectly healthy. The bypass is safe here
	// because the query selects at most one identifier and discards it.
	sysCtx := privacy.NewBypassContext(ctx)
	_, err := f.defaultClient.Tenant.Query().Limit(1).IDs(sysCtx)
	return err
}

// Close shuts down the default pool and every dedicated pool.
//
// It attempts all of them even after one fails, so a single bad pool cannot
// leak the rest, and returns a combined error naming each failure. Called
// during shutdown; the factory is unusable afterwards.
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
