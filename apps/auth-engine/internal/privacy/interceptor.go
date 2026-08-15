/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/privacy/interceptor.go
 * Tier: Security & Privacy Layer / ORM Boundary Enforcement
 *
 * Applies the tenant boundary at the ORM, so that isolation does not depend on
 * every query remembering to ask for it.
 *
 * Tenant isolation enforced by convention fails the first time someone writes a
 * query without the filter, and that omission looks exactly like correct code
 * in review. Here the filter is added beneath the query builder: a repository
 * method cannot opt out, and one that forgets is still confined.
 *
 * Enforcement is fail-closed in two directions. A query with no tenant in
 * context is refused rather than run unfiltered, and an entity type with no
 * rule in the switch below is refused rather than allowed through. That second
 * rule is what makes adding an entity safe: a new type nobody remembered to
 * scope breaks loudly on its first query instead of silently returning every
 * tenant's rows.
 *
 * Entities are scoped one of two ways. Those carrying tenant_id are filtered on
 * it directly; those that do not are filtered through the parent that does, so
 * a session is reachable only via a user in the caller's tenant.
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/managedtenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/permission"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/pushdevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/securityblacklist"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/socialauthstate"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/trusteddevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/useripsubnethistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userpasswordhistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/webhookendpoint"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/webhookevent"
)

// ErrPrivacyViolation reports that a query or mutation was refused for want of
// a tenant scope, or because its entity type has no rule here.
//
// It is an internal fault, not a client one: reaching it means code issued a
// query without establishing scope first. Handlers should map it to a generic
// 500 rather than surfacing the detail, which names internal entity types.
var ErrPrivacyViolation = errors.New("privacy boundary violation: missing required tenant or environment scope in context")

// AttachPrivacyInterceptors installs tenant boundary enforcement on an Ent
// client, for both reads and writes.
//
// Call it once per client, immediately after opening it and before any query
// runs. A client that misses this has no isolation at all.
func AttachPrivacyInterceptors(client *ent.Client) {
	// Read path: narrow every query to the caller's tenant, or refuse it.
	client.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
			p, ok := FromContext(ctx)
			if ok && p.Bypass {
				return next.Query(ctx, q)
			}

			// Each case adds its own filter. There is no shared fallback: a type
			// absent from this switch reaches the default and is refused.
			switch query := q.(type) {

			// Entities carrying tenant_id, filtered on it directly. Those that
			// also carry an environment are narrowed by it when one is set.
			case *ent.TenantQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Tenant query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(tenant.ID(p.TenantID))

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

			case *ent.RoleQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Role query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(role.TenantID(p.TenantID))

			case *ent.WebhookEndpointQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: WebhookEndpoint query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(webhookendpoint.TenantID(p.TenantID))

			case *ent.SecurityBlacklistQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: SecurityBlacklist query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(securityblacklist.TenantID(p.TenantID))

			case *ent.SocialAuthStateQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: SocialAuthState query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(socialauthstate.TenantID(p.TenantID))

			// ManagedTenant is control-plane data: its tenant_id is the platform
			// tenant, not the customer tenant the row describes. Filtering on
			// tenant_id therefore confines these rows to the control plane, which
			// is what stops one hosted customer reading another's ownership
			// records. The managed_tenant_id it points at is deliberately not
			// filtered here — resolving that to a Tenant row requires a confined
			// bypass, performed only after this scope has authorized the caller.
			case *ent.ManagedTenantQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: ManagedTenant query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(managedtenant.TenantID(p.TenantID))

			// Entities with no tenant_id of their own, reached through the
			// parent that has one. The join is the boundary: a row is visible
			// only when its parent belongs to the caller's tenant.
			case *ent.ApiKeyQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: ApiKey query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(apikey.HasApplicationWith(application.TenantID(p.TenantID)))
				if p.Environment != "" {
					query.Where(apikey.EnvironmentEQ(apikey.Environment(p.Environment)))
				}

			case *ent.WebhookEventQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: WebhookEvent query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(webhookevent.HasWebhookEndpointWith(webhookendpoint.TenantID(p.TenantID)))

			case *ent.PermissionQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Permission query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(permission.HasRoleWith(role.TenantID(p.TenantID)))

			case *ent.UserRoleQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: UserRole query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(userrole.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.SessionQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Session query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(session.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.IdentityQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: Identity query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(identity.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.OrgMemberQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: OrgMember query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(orgmember.HasOrganizationWith(organization.TenantID(p.TenantID)))

			case *ent.OrgInvitationQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: OrgInvitation query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(orginvitation.HasOrganizationWith(organization.TenantID(p.TenantID)))

			case *ent.PushDeviceQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: PushDevice query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(pushdevice.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.RecoveryContactQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: RecoveryContact query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(recoverycontact.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.RecoveryRequestQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: RecoveryRequest query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(recoveryrequest.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.SAMLConnectionQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: SAMLConnection query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(samlconnection.HasOrganizationWith(organization.TenantID(p.TenantID)))

			case *ent.TrustedDeviceQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: TrustedDevice query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(trusteddevice.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.TwoFactorMethodQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: TwoFactorMethod query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(twofactormethod.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.UserIpSubnetHistoryQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: UserIpSubnetHistory query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(useripsubnethistory.HasUserWith(user.TenantID(p.TenantID)))

			case *ent.UserPasswordHistoryQuery:
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: UserPasswordHistory query requires active TenantID in context", ErrPrivacyViolation)
				}
				query.Where(userpasswordhistory.HasUserWith(user.TenantID(p.TenantID)))

			// Unhandled entity types are refused. Falling through to an
			// unfiltered query would return every tenant's rows, so a type
			// added to the schema without a rule here fails on first use.
			default:
				return nil, fmt.Errorf("%w: unhandled entity type '%T' in privacy interceptor — explicit tenant scoping rule required", ErrPrivacyViolation, q)
			}

			return next.Query(ctx, q)
		})
	}))

	// Write path: stamp the caller's tenant onto new rows, and refuse writes
	// that have no tenant to stamp.
	client.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			p, ok := FromContext(ctx)
			if ok && p.Bypass {
				return next.Mutate(ctx, m)
			}

			// A mutation exposing SetTenantID is one on a tenant-scoped entity;
			// anything else needs no stamping here and is covered on read.
			if setter, okMut := m.(interface{ SetTenantID(string) }); okMut {
				if !ok || p.TenantID == "" {
					return nil, fmt.Errorf("%w: mutation on multi-tenant entity requires active TenantID in context", ErrPrivacyViolation)
				}
				// Fill the tenant only when the caller left it unset. Overwriting
				// an explicit value would mask a caller writing across tenants
				// instead of letting the boundary check catch it.
				if tID, exists := m.Field("tenant_id"); !exists || tID == "" {
					setter.SetTenantID(p.TenantID)
				}
			}

			return next.Mutate(ctx, m)
		})
	})
}
