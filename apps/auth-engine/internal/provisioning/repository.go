/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/provisioning/repository.go
 * Tier: Internal Feature Package / Tenant Provisioning Data Access
 *
 * Database writes that establish a tenant.
 *
 * Every query here runs under a privacy bypass, which is safe for one specific
 * reason: these operations create or locate the tenant boundary itself, so
 * there is no tenant to scope by yet. The bypass never escapes this file — the
 * contexts built here are local, and callers get plain values back.
 *
 * The writes pin tenant ownership explicitly with SetTenantID rather than
 * relying on the privacy interceptor's write hook, which cannot help under a
 * bypass. Being explicit also documents which tenant each row belongs to at the
 * point of creation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package provisioning

import (
	"context"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// Service provisions tenants.
type Service struct {
	// repo performs the bypassed writes that establish a tenant.
	repo *Repository
	// keys mints the tenant's first API key pair.
	keys *apikey.Service
}

// NewService constructs a provisioning service.
//
// keys must be the same apikey.Service the rest of the engine uses, so that
// generated credentials are peppered with the deployment's configured secret
// and validate on the request path.
func NewService(factory *clientfactory.ClientFactory, keys *apikey.Service) *Service {
	return &Service{
		repo: &Repository{factory: factory},
		keys: keys,
	}
}

// Repository writes the rows a tenant is made of.
type Repository struct {
	// factory supplies the database client.
	factory *clientfactory.ClientFactory
}

// FindTenantBySlug returns the tenant owning slug, or nil when none does.
//
// This is what makes provisioning idempotent, so it must not treat "no such
// tenant" as an error: a nil result is the ordinary outcome for a new tenant.
func (r *Repository) FindTenantBySlug(ctx context.Context, slug string) (*ent.Tenant, error) {
	sysCtx := privacy.NewBypassContext(ctx)
	t, err := r.factory.GetClient(sysCtx, "", "").Tenant.Query().
		Where(tenant.Slug(slug)).
		Only(sysCtx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed looking up tenant by slug %q: %w", slug, err)
	}
	return t, nil
}

// CreateTenant inserts the tenant row.
//
// claimFirstAdmin pre-closes the one-time first-admin slot. Leaving it false —
// the customer case — lets the first person to sign up claim tenant_admin
// atomically through the existing ClaimFirstAdminRole path. Setting it true is
// for the platform tenant, whose publishable key is public by construction and
// whose administrator must therefore never be decided by whoever signs up first.
//
// Returns an error when the insert fails; a uniqueness conflict means a
// concurrent caller won the same slug and the caller should re-read.
func (r *Repository) CreateTenant(ctx context.Context, tenantID, name, slug string, claimFirstAdmin bool) error {
	sysCtx := privacy.NewBypassContext(ctx)
	_, err := r.factory.GetClient(sysCtx, tenantID, envTest).Tenant.Create().
		SetID(tenantID).
		SetName(name).
		SetSlug(slug).
		SetFirstAdminClaimed(claimFirstAdmin).
		Save(sysCtx)
	if err != nil {
		return fmt.Errorf("failed creating tenant %s: %w", tenantID, err)
	}
	return nil
}

// CreateApplication inserts the tenant's first application.
//
// redirectURIs and corsOrigins may be empty. An empty CORS list means "not
// configured", which leaves origin checking to the deployment-wide policy
// rather than refusing every browser request.
func (r *Repository) CreateApplication(ctx context.Context, appID, tenantID, name, env string,
	redirectURIs []string, corsOrigins []string) error {

	sysCtx := privacy.NewBypassContext(ctx)
	builder := r.factory.GetClient(sysCtx, tenantID, env).Application.Create().
		SetID(appID).
		SetTenantID(tenantID).
		SetName(name).
		SetEnvironment(application.Environment(env))

	if len(redirectURIs) > 0 {
		builder = builder.SetExactRedirectUris(redirectURIs)
	}
	if len(corsOrigins) > 0 {
		builder = builder.SetAllowedCorsOrigins(corsOrigins)
	}

	if _, err := builder.Save(sysCtx); err != nil {
		return fmt.Errorf("failed creating application %s for tenant %s: %w", appID, tenantID, err)
	}
	return nil
}

// EnsureSystemRoles installs the tenant's system roles and reports how many it
// has afterwards.
//
// It delegates to rbac.EnsureSystemRoles so the role set has exactly one
// definition; a tenant provisioned here and one seeded for development must not
// differ in which roles exist.
func (r *Repository) EnsureSystemRoles(ctx context.Context, tenantID string) (int, error) {
	sysCtx := privacy.NewBypassContext(ctx)
	roles, err := rbac.EnsureSystemRoles(sysCtx, r.factory.GetClient(sysCtx, tenantID, envTest), tenantID)
	if err != nil {
		return 0, err
	}
	return len(roles), nil
}
