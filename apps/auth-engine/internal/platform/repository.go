/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/platform/repository.go
 * Tier: Internal Feature Package / Control-Plane Data Access
 *
 * Ownership records for the hosted control plane.
 *
 * A ManagedTenant row says "this platform user owns that customer tenant". Its
 * own tenant_id is the PLATFORM tenant, not the tenant it describes, so the
 * privacy interceptor confines these rows to the control plane exactly as it
 * confines any other tenant-owned row — which is what stops one hosted customer
 * reading another's ownership records.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/managedtenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

// Repository reads and writes control-plane ownership records.
type Repository struct {
	// factory supplies the database client.
	factory *clientfactory.ClientFactory
}

// NewRepository constructs the control-plane repository.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// OwnedTenant is one customer tenant a platform user owns, joined to the
// tenant's own display fields.
type OwnedTenant struct {
	// ID and Slug identify the customer tenant.
	ID   string
	Slug string
	// Name is the tenant's display name.
	Name string
	// Role is the caller's relationship to it: "owner" or "member".
	Role string
	// AcquiredAt is when the ownership record was created, which for an owner is
	// when they provisioned the tenant.
	AcquiredAt time.Time
}

// RecordOwnership inserts the row naming ownerUserID as the owner of
// managedTenantID.
//
// platformTenantID is set explicitly even though the interceptor would stamp it:
// being explicit documents at the write site that this row belongs to the
// control plane rather than to the tenant it describes, and a value disagreeing
// with the request's scope is refused by the interceptor instead of silently
// landing under the wrong tenant.
func (r *Repository) RecordOwnership(ctx context.Context, platformTenantID, ownerUserID, managedTenantID string) error {
	_, err := r.factory.GetClient(ctx, "", "").ManagedTenant.Create().
		SetID(idgen.New("mtn")).
		SetTenantID(platformTenantID).
		SetOwnerUserID(ownerUserID).
		SetManagedTenantID(managedTenantID).
		SetRole(managedtenant.RoleOwner).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed recording ownership of tenant %s: %w", managedTenantID, err)
	}
	return nil
}

// OwnedTenants returns the customer tenants ownerUserID has a record for, newest
// first.
//
// The read is two-stage by necessity. Ownership rows come back under the
// request's own control-plane scope, so the interceptor has already confined
// them to the platform tenant and this query further narrows them to one user.
// Resolving the customer tenants those rows point at then requires a bypass: a
// scoped Tenant query is rewritten to "AND id = <platform tenant>" and would
// return nothing at all.
//
// The bypass is confined to that second query and is safe only because of the
// order: authorization happens first, and the ID set it produces comes from rows
// the caller demonstrably owns. An ID set derived from request input must never
// be passed here — that would turn the bypass into a read of any tenant the
// caller cares to name.
func (r *Repository) OwnedTenants(ctx context.Context, ownerUserID string) ([]OwnedTenant, error) {
	rows, err := r.factory.GetClient(ctx, "", "").ManagedTenant.Query().
		Where(managedtenant.OwnerUserID(ownerUserID)).
		Order(ent.Desc(managedtenant.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed listing ownership records: %w", err)
	}
	if len(rows) == 0 {
		return []OwnedTenant{}, nil
	}

	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ManagedTenantID)
	}

	sysCtx := privacy.NewBypassContext(ctx)
	tenants, err := r.factory.GetClient(sysCtx, "", "").Tenant.Query().
		Where(tenant.IDIn(ids...)).
		All(sysCtx)
	if err != nil {
		return nil, fmt.Errorf("failed resolving owned tenants: %w", err)
	}

	byID := make(map[string]*ent.Tenant, len(tenants))
	for _, t := range tenants {
		byID[t.ID] = t
	}

	// The ownership rows drive the output order and membership. A tenant that has
	// since been deleted leaves a row pointing at nothing; it is skipped rather
	// than reported with empty fields, which would read as a tenant named "".
	out := make([]OwnedTenant, 0, len(rows))
	for _, row := range rows {
		t, ok := byID[row.ManagedTenantID]
		if !ok {
			continue
		}
		out = append(out, OwnedTenant{
			ID:         t.ID,
			Slug:       t.Slug,
			Name:       t.Name,
			Role:       string(row.Role),
			AcquiredAt: row.CreatedAt.UTC(),
		})
	}
	return out, nil
}
