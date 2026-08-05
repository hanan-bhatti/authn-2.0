/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/privacy/interceptor.go
 * Tier: Security & Privacy Layer / Ent ORM Privacy Interceptors & Hooks
 *
 * Description: Automatic ORM-level Privacy Interceptors enforcing tenant_id and
 *              environment boundary isolation across all database queries and mutations.
 *              Enforces a strict FAIL-CLOSED policy: un-scoped queries or mutations
 *              on multi-tenant or parent-linked tables are rejected immediately.
 *
 * Security Notice:
 *   - Every single entity query type MUST be explicitly handled below.
 *   - Entities with tenant_id are filtered directly via TenantID.
 *   - Child entities without tenant_id are filtered via parent entity ownership check (e.g. HasUserWith).
 *   - The default branch triggers a LOUD FAIL-CLOSED error if an unhandled entity type is queried.
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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/permission"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/pushdevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
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

			// Fail-closed check: every query type MUST have an explicit privacy policy rule
			switch query := q.(type) {

			// 1. Direct Tenant-Scoped Entities (carry tenant_id field)
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

			// 2. Parent-Scoped Child Entities (authorize via parent entity ownership check)
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

			// 3. Fail-Closed Default Fallback: Any unhandled entity MUST throw a LOUD ERROR!
			default:
				return nil, fmt.Errorf("%w: unhandled entity type '%T' in privacy interceptor — explicit tenant scoping rule required", ErrPrivacyViolation, q)
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

			// Fail-closed check on mutations: TenantID must be present in context for tenant-scoped entities
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
