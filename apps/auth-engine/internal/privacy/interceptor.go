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
 * Both directions of traffic are covered. Reads are narrowed to the caller's
 * tenant. Writes are narrowed too, on the same predicates from scope.go, which
 * matters because a row identifier usually arrives in the request: an endpoint
 * that names a user by ID would otherwise reach any tenant's user, and the write
 * would succeed even though a read of the same row returns nothing. Creates are
 * the exception — they have nothing to match — so instead of a filter they are
 * stamped with the caller's tenant.
 *
 * Enforcement is fail-closed in two directions. An operation with no tenant in
 * context is refused rather than run unfiltered, and an entity type with no rule
 * in the switch below is refused rather than allowed through. That second rule is
 * what makes adding an entity safe: a new type nobody remembered to scope breaks
 * loudly on its first use instead of silently spanning every tenant.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package privacy

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
)

// ErrPrivacyViolation reports that a query or mutation was refused for want of
// a tenant scope, or because its entity type has no rule here.
//
// It is an internal fault, not a client one: reaching it means code issued a
// query without establishing scope first. Handlers should map it to a generic
// 500 rather than surfacing the detail, which names internal entity types.
var ErrPrivacyViolation = errors.New("privacy boundary violation: missing required tenant or environment scope in context")

// scopeError reports an operation refused for want of a tenant, naming the
// entity so the log points at the call site that skipped establishing scope.
func scopeError(entity, operation string) error {
	return fmt.Errorf("%w: %s %s requires active TenantID in context", ErrPrivacyViolation, entity, operation)
}

// unhandledError reports an entity type with no rule in one of the switches.
func unhandledError(v any, operation string) error {
	return fmt.Errorf("%w: unhandled entity type '%T' in privacy interceptor — explicit tenant scoping rule required for %s", ErrPrivacyViolation, v, operation)
}

// AttachPrivacyInterceptors installs tenant boundary enforcement on an Ent
// client, for both reads and writes.
//
// Call it once per client, immediately after opening it and before any query
// runs. A client that misses this has no isolation at all.
func AttachPrivacyInterceptors(client *ent.Client) {
	client.Intercept(ent.InterceptFunc(scopeQuery))
	client.Use(scopeMutation)
}

// scopeQuery narrows every query to the caller's tenant, or refuses it.
func scopeQuery(next ent.Querier) ent.Querier {
	return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) {
		p, ok := FromContext(ctx)
		if ok && p.Bypass {
			return next.Query(ctx, q)
		}
		scoped := ok && p.TenantID != ""

		// Each case adds its own filter. There is no shared fallback: a type
		// absent from this switch reaches the default and is refused.
		switch query := q.(type) {

		case *ent.TenantQuery:
			if !scoped {
				return nil, scopeError("Tenant", "query")
			}
			query.Where(tenantScope(p)...)

		case *ent.UserQuery:
			if !scoped {
				return nil, scopeError("User", "query")
			}
			query.Where(userScope(p)...)

		case *ent.ApplicationQuery:
			if !scoped {
				return nil, scopeError("Application", "query")
			}
			query.Where(applicationScope(p)...)

		case *ent.OrganizationQuery:
			if !scoped {
				return nil, scopeError("Organization", "query")
			}
			query.Where(organizationScope(p)...)

		case *ent.AuditLogQuery:
			if !scoped {
				return nil, scopeError("AuditLog", "query")
			}
			query.Where(auditLogScope(p)...)

		case *ent.RoleQuery:
			if !scoped {
				return nil, scopeError("Role", "query")
			}
			query.Where(roleScope(p)...)

		case *ent.WebhookEndpointQuery:
			if !scoped {
				return nil, scopeError("WebhookEndpoint", "query")
			}
			query.Where(webhookEndpointScope(p)...)

		case *ent.SecurityBlacklistQuery:
			if !scoped {
				return nil, scopeError("SecurityBlacklist", "query")
			}
			query.Where(securityBlacklistScope(p)...)

		case *ent.SocialAuthStateQuery:
			if !scoped {
				return nil, scopeError("SocialAuthState", "query")
			}
			query.Where(socialAuthStateScope(p)...)

		case *ent.ManagedTenantQuery:
			if !scoped {
				return nil, scopeError("ManagedTenant", "query")
			}
			query.Where(managedTenantScope(p)...)

		case *ent.ApiKeyQuery:
			if !scoped {
				return nil, scopeError("ApiKey", "query")
			}
			query.Where(apiKeyScope(p)...)

		case *ent.WebhookEventQuery:
			if !scoped {
				return nil, scopeError("WebhookEvent", "query")
			}
			query.Where(webhookEventScope(p)...)

		case *ent.PermissionQuery:
			if !scoped {
				return nil, scopeError("Permission", "query")
			}
			query.Where(permissionScope(p)...)

		case *ent.UserRoleQuery:
			if !scoped {
				return nil, scopeError("UserRole", "query")
			}
			query.Where(userRoleScope(p)...)

		case *ent.SessionQuery:
			if !scoped {
				return nil, scopeError("Session", "query")
			}
			query.Where(sessionScope(p)...)

		case *ent.SessionAppActivityQuery:
			if !scoped {
				return nil, scopeError("SessionAppActivity", "query")
			}
			query.Where(sessionAppActivityScope(p)...)

		case *ent.IdentityQuery:
			if !scoped {
				return nil, scopeError("Identity", "query")
			}
			query.Where(identityScope(p)...)

		case *ent.OrgMemberQuery:
			if !scoped {
				return nil, scopeError("OrgMember", "query")
			}
			query.Where(orgMemberScope(p)...)

		case *ent.OrgInvitationQuery:
			if !scoped {
				return nil, scopeError("OrgInvitation", "query")
			}
			query.Where(orgInvitationScope(p)...)

		case *ent.PushDeviceQuery:
			if !scoped {
				return nil, scopeError("PushDevice", "query")
			}
			query.Where(pushDeviceScope(p)...)

		case *ent.RecoveryContactQuery:
			if !scoped {
				return nil, scopeError("RecoveryContact", "query")
			}
			query.Where(recoveryContactScope(p)...)

		case *ent.RecoveryRequestQuery:
			if !scoped {
				return nil, scopeError("RecoveryRequest", "query")
			}
			query.Where(recoveryRequestScope(p)...)

		case *ent.SAMLConnectionQuery:
			if !scoped {
				return nil, scopeError("SAMLConnection", "query")
			}
			query.Where(samlConnectionScope(p)...)

		case *ent.TrustedDeviceQuery:
			if !scoped {
				return nil, scopeError("TrustedDevice", "query")
			}
			query.Where(trustedDeviceScope(p)...)

		case *ent.TwoFactorMethodQuery:
			if !scoped {
				return nil, scopeError("TwoFactorMethod", "query")
			}
			query.Where(twoFactorMethodScope(p)...)

		case *ent.UserIpSubnetHistoryQuery:
			if !scoped {
				return nil, scopeError("UserIpSubnetHistory", "query")
			}
			query.Where(userIPSubnetHistoryScope(p)...)

		case *ent.UserPasswordHistoryQuery:
			if !scoped {
				return nil, scopeError("UserPasswordHistory", "query")
			}
			query.Where(userPasswordHistoryScope(p)...)

		// Unhandled entity types are refused. Falling through to an
		// unfiltered query would return every tenant's rows, so a type
		// added to the schema without a rule here fails on first use.
		default:
			return nil, unhandledError(q, "query")
		}

		return next.Query(ctx, q)
	})
}

// scopeMutation confines every write to the caller's tenant.
//
// Updates and deletes are narrowed by the same predicates the read path uses,
// so a row identifier taken from a request reaches only rows the caller could
// have read. Without that, a cross-tenant identifier produces a successful write
// against a row the caller cannot see — the failure mode is silent on the
// writing side and invisible on the owning side. A narrowed update that matches
// nothing surfaces as ent's not-found error, which handlers already render as a
// 404, so a cross-tenant identifier is indistinguishable from an unknown one.
//
// Creates cannot be narrowed, having no row to match, and are stamped with the
// caller's tenant instead.
func scopeMutation(next ent.Mutator) ent.Mutator {
	return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		p, ok := FromContext(ctx)
		if ok && p.Bypass {
			return next.Mutate(ctx, m)
		}

		if m.Op().Is(ent.OpCreate) {
			if err := stampTenant(m, p, ok); err != nil {
				return nil, err
			}
			return next.Mutate(ctx, m)
		}

		if err := narrowMutation(m, p, ok && p.TenantID != ""); err != nil {
			return nil, err
		}
		return next.Mutate(ctx, m)
	})
}

// stampTenant sets the caller's tenant on a new row.
//
// A mutation exposing SetTenantID is one on a tenant-scoped entity; anything
// else carries its tenant through a parent and needs no stamping. An explicitly
// named tenant that disagrees with the caller's is refused rather than
// corrected: rewriting it would turn an attempt to write across tenants into a
// successful write somewhere else, which looks identical to working code from
// the outside, where refusing surfaces the caller that is trusting a tenant it
// never verified.
func stampTenant(m ent.Mutation, p *PrivacyContext, ok bool) error {
	setter, isScoped := m.(interface{ SetTenantID(string) })
	if !isScoped {
		return nil
	}
	if !ok || p.TenantID == "" {
		return fmt.Errorf("%w: mutation on multi-tenant entity requires active TenantID in context", ErrPrivacyViolation)
	}

	named, explicit := m.Field("tenant_id")
	namedID, _ := named.(string)

	switch {
	case explicit && namedID != "" && namedID != p.TenantID:
		return fmt.Errorf("%w: mutation names tenant %q under a context scoped to tenant %q",
			ErrPrivacyViolation, namedID, p.TenantID)
	case !explicit || namedID == "":
		setter.SetTenantID(p.TenantID)
	}
	return nil
}

// narrowMutation adds the caller's tenant filter to an update or delete.
//
// The switch mirrors the read path case for case, drawing on the same scope
// functions, and refuses an entity type it does not recognise for the same
// reason the read path does.
func narrowMutation(m ent.Mutation, p *PrivacyContext, scoped bool) error {
	switch mut := m.(type) {

	case *ent.TenantMutation:
		if !scoped {
			return scopeError("Tenant", "mutation")
		}
		mut.Where(tenantScope(p)...)

	case *ent.UserMutation:
		if !scoped {
			return scopeError("User", "mutation")
		}
		mut.Where(userScope(p)...)

	case *ent.ApplicationMutation:
		if !scoped {
			return scopeError("Application", "mutation")
		}
		mut.Where(applicationScope(p)...)

	case *ent.OrganizationMutation:
		if !scoped {
			return scopeError("Organization", "mutation")
		}
		mut.Where(organizationScope(p)...)

	case *ent.AuditLogMutation:
		if !scoped {
			return scopeError("AuditLog", "mutation")
		}
		mut.Where(auditLogScope(p)...)

	case *ent.RoleMutation:
		if !scoped {
			return scopeError("Role", "mutation")
		}
		mut.Where(roleScope(p)...)

	case *ent.WebhookEndpointMutation:
		if !scoped {
			return scopeError("WebhookEndpoint", "mutation")
		}
		mut.Where(webhookEndpointScope(p)...)

	case *ent.SecurityBlacklistMutation:
		if !scoped {
			return scopeError("SecurityBlacklist", "mutation")
		}
		mut.Where(securityBlacklistScope(p)...)

	case *ent.SocialAuthStateMutation:
		if !scoped {
			return scopeError("SocialAuthState", "mutation")
		}
		mut.Where(socialAuthStateScope(p)...)

	case *ent.ManagedTenantMutation:
		if !scoped {
			return scopeError("ManagedTenant", "mutation")
		}
		mut.Where(managedTenantScope(p)...)

	case *ent.ApiKeyMutation:
		if !scoped {
			return scopeError("ApiKey", "mutation")
		}
		mut.Where(apiKeyScope(p)...)

	case *ent.WebhookEventMutation:
		if !scoped {
			return scopeError("WebhookEvent", "mutation")
		}
		mut.Where(webhookEventScope(p)...)

	case *ent.PermissionMutation:
		if !scoped {
			return scopeError("Permission", "mutation")
		}
		mut.Where(permissionScope(p)...)

	case *ent.UserRoleMutation:
		if !scoped {
			return scopeError("UserRole", "mutation")
		}
		mut.Where(userRoleScope(p)...)

	case *ent.SessionMutation:
		if !scoped {
			return scopeError("Session", "mutation")
		}
		mut.Where(sessionScope(p)...)

	case *ent.SessionAppActivityMutation:
		if !scoped {
			return scopeError("SessionAppActivity", "mutation")
		}
		mut.Where(sessionAppActivityScope(p)...)

	case *ent.IdentityMutation:
		if !scoped {
			return scopeError("Identity", "mutation")
		}
		mut.Where(identityScope(p)...)

	case *ent.OrgMemberMutation:
		if !scoped {
			return scopeError("OrgMember", "mutation")
		}
		mut.Where(orgMemberScope(p)...)

	case *ent.OrgInvitationMutation:
		if !scoped {
			return scopeError("OrgInvitation", "mutation")
		}
		mut.Where(orgInvitationScope(p)...)

	case *ent.PushDeviceMutation:
		if !scoped {
			return scopeError("PushDevice", "mutation")
		}
		mut.Where(pushDeviceScope(p)...)

	case *ent.RecoveryContactMutation:
		if !scoped {
			return scopeError("RecoveryContact", "mutation")
		}
		mut.Where(recoveryContactScope(p)...)

	case *ent.RecoveryRequestMutation:
		if !scoped {
			return scopeError("RecoveryRequest", "mutation")
		}
		mut.Where(recoveryRequestScope(p)...)

	case *ent.SAMLConnectionMutation:
		if !scoped {
			return scopeError("SAMLConnection", "mutation")
		}
		mut.Where(samlConnectionScope(p)...)

	case *ent.TrustedDeviceMutation:
		if !scoped {
			return scopeError("TrustedDevice", "mutation")
		}
		mut.Where(trustedDeviceScope(p)...)

	case *ent.TwoFactorMethodMutation:
		if !scoped {
			return scopeError("TwoFactorMethod", "mutation")
		}
		mut.Where(twoFactorMethodScope(p)...)

	case *ent.UserIpSubnetHistoryMutation:
		if !scoped {
			return scopeError("UserIpSubnetHistory", "mutation")
		}
		mut.Where(userIPSubnetHistoryScope(p)...)

	case *ent.UserPasswordHistoryMutation:
		if !scoped {
			return scopeError("UserPasswordHistory", "mutation")
		}
		mut.Where(userPasswordHistoryScope(p)...)

	default:
		return unhandledError(m, "mutation")
	}

	return nil
}
