/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/privacy/interceptor.go
 * Tier: Security & Privacy Layer / Ent ORM Privacy Interceptors & Hooks
 *
 * Description: Automatic ORM-level Privacy Interceptors enforcing tenant_id and
 *              environment boundary isolation across all database queries and mutations.
 *              Enforces a strict FAIL-CLOSED policy: un-scoped queries on multi-tenant
 *              tables are rejected immediately.
 *
 * Security Notice:
 *   - Any database query on tenant-scoped schemas without an active TenantID in context
 *     (or an explicit system Bypass) is REJECTED with ErrPrivacyViolation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package privacy

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

var (
	ErrPrivacyViolation = errors.New("privacy boundary violation: missing required tenant or environment scope in context")
)

// AttachPrivacyInterceptors attaches automatic fail-closed tenant and environment boundary enforcement to an Ent client.
func AttachPrivacyInterceptors(client *ent.Client) {
	// Intercept queries and enforce fail-closed tenant & environment boundaries
	client.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
			p, ok := FromContext(ctx)
			if ok && p.Bypass {
				return next.Query(ctx, q)
			}

			// Fail-closed check: tenant-scoped queries require an active PrivacyContext with TenantID
			switch query := q.(type) {
			case *ent.UserQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: User query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(user.TenantID(p.TenantID))
				if p.Environment != "" {
					query.Where(user.EnvironmentEQ(user.Environment(p.Environment)))
				}

			case *ent.ApplicationQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Application query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(application.TenantID(p.TenantID))
				if p.Environment != "" {
					query.Where(application.EnvironmentEQ(application.Environment(p.Environment)))
				}

			case *ent.ApiKeyQuery:
				if ok && p.Environment != "" {
					query.Where(apikey.EnvironmentEQ(apikey.Environment(p.Environment)))
				}

			case *ent.OrganizationQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Organization query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(organization.TenantID(p.TenantID))

			case *ent.AuditLogQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: AuditLog query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(auditlog.TenantID(p.TenantID))

			case *ent.TenantQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Tenant query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(tenant.ID(p.TenantID))

			case *ent.SessionQuery, *ent.OrgMemberQuery, *ent.OrgInvitationQuery, *ent.IdentityQuery:
				if !ok {
					return nil, fmt.Errorf("%w: query requires active PrivacyContext in context", ErrPrivacyViolation)
				}
			}

			return next.Query(ctx, q)
		})
	}))

	// Intercept mutations to enforce fail-closed tenant scoping on new entity creations
	client.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			p, ok := FromContext(ctx)
			if ok && p.Bypass {
				return next.Mutate(ctx, m)
			}

			// Fail-closed check on mutations: TenantID must be present in context
			if setter, okMut := m.(interface{ SetTenantID(string) }); okMut {
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: mutation on multi-tenant entity requires active TenantID in context", ErrPrivacyViolation)
				}
				if tID, exists := m.Field("tenant_id"); !exists || tID == "" {
					setter.SetTenantID(p.TenantID)
				}
			}

			return next.Mutate(ctx, m)
		})
	})
}
