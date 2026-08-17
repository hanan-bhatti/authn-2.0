/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/privacy/scope.go
 * Tier: Security & Privacy Layer / Tenant Boundary Definitions
 *
 * The tenant filter for every entity in the schema, one definition per type.
 *
 * Both the read and the write interceptor take their filter from here. A rule
 * defined twice can be tightened in one place and left loose in the other, and
 * the two paths fail differently when that happens: a loose read returns another
 * tenant's rows, where a loose write modifies them. Sharing the definition makes
 * "reads and writes are confined identically" a property of the code rather than
 * something a reviewer has to check.
 *
 * Entities are scoped one of two ways, mirroring the schema. Those carrying
 * tenant_id are filtered on it directly; those that do not are filtered through
 * the parent that does, so a session is reachable only via a user in the
 * caller's tenant. Where an entity also carries an environment, it is narrowed
 * by that too whenever the context names one — an empty environment spans both,
 * which is what a credential lookup needs before the environment is known.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package privacy

import (
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/managedtenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/organization"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orginvitation"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/permission"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/predicate"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/pushdevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/role"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/samlconnection"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/securityblacklist"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sessionappactivity"
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

// Entities carrying tenant_id, filtered on it directly.

func tenantScope(p *PrivacyContext) []predicate.Tenant {
	return []predicate.Tenant{tenant.ID(p.TenantID)}
}

func userScope(p *PrivacyContext) []predicate.User {
	preds := []predicate.User{user.TenantID(p.TenantID)}
	if p.Environment != "" {
		preds = append(preds, user.EnvironmentEQ(user.Environment(p.Environment)))
	}
	return preds
}

func applicationScope(p *PrivacyContext) []predicate.Application {
	preds := []predicate.Application{application.TenantID(p.TenantID)}
	if p.Environment != "" {
		preds = append(preds, application.EnvironmentEQ(application.Environment(p.Environment)))
	}
	return preds
}

func organizationScope(p *PrivacyContext) []predicate.Organization {
	return []predicate.Organization{organization.TenantID(p.TenantID)}
}

func auditLogScope(p *PrivacyContext) []predicate.AuditLog {
	return []predicate.AuditLog{auditlog.TenantID(p.TenantID)}
}

func roleScope(p *PrivacyContext) []predicate.Role {
	return []predicate.Role{role.TenantID(p.TenantID)}
}

func webhookEndpointScope(p *PrivacyContext) []predicate.WebhookEndpoint {
	return []predicate.WebhookEndpoint{webhookendpoint.TenantID(p.TenantID)}
}

func securityBlacklistScope(p *PrivacyContext) []predicate.SecurityBlacklist {
	return []predicate.SecurityBlacklist{securityblacklist.TenantID(p.TenantID)}
}

func socialAuthStateScope(p *PrivacyContext) []predicate.SocialAuthState {
	return []predicate.SocialAuthState{socialauthstate.TenantID(p.TenantID)}
}

// managedTenantScope confines control-plane ownership records.
//
// A ManagedTenant's tenant_id is the platform tenant that operates the record,
// not the customer tenant the record describes, so filtering on it is what stops
// one hosted customer reading or editing another's ownership row. The
// managed_tenant_id it points at is deliberately not filtered: resolving that to
// a Tenant row needs a confined bypass, performed only after this scope has
// authorized the caller.
func managedTenantScope(p *PrivacyContext) []predicate.ManagedTenant {
	return []predicate.ManagedTenant{managedtenant.TenantID(p.TenantID)}
}

// Entities with no tenant_id of their own, reached through the parent that has
// one. The join is the boundary: a row is in scope only when its parent belongs
// to the caller's tenant.

func apiKeyScope(p *PrivacyContext) []predicate.ApiKey {
	preds := []predicate.ApiKey{apikey.HasApplicationWith(application.TenantID(p.TenantID))}
	if p.Environment != "" {
		preds = append(preds, apikey.EnvironmentEQ(apikey.Environment(p.Environment)))
	}
	return preds
}

func webhookEventScope(p *PrivacyContext) []predicate.WebhookEvent {
	return []predicate.WebhookEvent{
		webhookevent.HasWebhookEndpointWith(webhookendpoint.TenantID(p.TenantID)),
	}
}

func permissionScope(p *PrivacyContext) []predicate.Permission {
	return []predicate.Permission{permission.HasRoleWith(role.TenantID(p.TenantID))}
}

func userRoleScope(p *PrivacyContext) []predicate.UserRole {
	return []predicate.UserRole{userrole.HasUserWith(user.TenantID(p.TenantID))}
}

func sessionScope(p *PrivacyContext) []predicate.Session {
	return []predicate.Session{session.HasUserWith(user.TenantID(p.TenantID))}
}

// sessionAppActivityScope requires both parents rather than either one.
//
// A row pairing a session with an application belongs to a tenant only if both
// sides do, and requiring both means a mismatched pairing — which nothing should
// be able to write — is in scope for neither tenant instead of for one of them.
func sessionAppActivityScope(p *PrivacyContext) []predicate.SessionAppActivity {
	preds := []predicate.SessionAppActivity{
		sessionappactivity.HasSessionWith(session.HasUserWith(user.TenantID(p.TenantID))),
		sessionappactivity.HasApplicationWith(application.TenantID(p.TenantID)),
	}
	if p.Environment != "" {
		preds = append(preds, sessionappactivity.HasApplicationWith(
			application.EnvironmentEQ(application.Environment(p.Environment)),
		))
	}
	return preds
}

func identityScope(p *PrivacyContext) []predicate.Identity {
	return []predicate.Identity{identity.HasUserWith(user.TenantID(p.TenantID))}
}

func orgMemberScope(p *PrivacyContext) []predicate.OrgMember {
	return []predicate.OrgMember{
		orgmember.HasOrganizationWith(organization.TenantID(p.TenantID)),
	}
}

func orgInvitationScope(p *PrivacyContext) []predicate.OrgInvitation {
	return []predicate.OrgInvitation{
		orginvitation.HasOrganizationWith(organization.TenantID(p.TenantID)),
	}
}

func pushDeviceScope(p *PrivacyContext) []predicate.PushDevice {
	return []predicate.PushDevice{pushdevice.HasUserWith(user.TenantID(p.TenantID))}
}

func recoveryContactScope(p *PrivacyContext) []predicate.RecoveryContact {
	return []predicate.RecoveryContact{recoverycontact.HasUserWith(user.TenantID(p.TenantID))}
}

func recoveryRequestScope(p *PrivacyContext) []predicate.RecoveryRequest {
	return []predicate.RecoveryRequest{recoveryrequest.HasUserWith(user.TenantID(p.TenantID))}
}

func samlConnectionScope(p *PrivacyContext) []predicate.SAMLConnection {
	return []predicate.SAMLConnection{
		samlconnection.HasOrganizationWith(organization.TenantID(p.TenantID)),
	}
}

func trustedDeviceScope(p *PrivacyContext) []predicate.TrustedDevice {
	return []predicate.TrustedDevice{trusteddevice.HasUserWith(user.TenantID(p.TenantID))}
}

func twoFactorMethodScope(p *PrivacyContext) []predicate.TwoFactorMethod {
	return []predicate.TwoFactorMethod{twofactormethod.HasUserWith(user.TenantID(p.TenantID))}
}

func userIPSubnetHistoryScope(p *PrivacyContext) []predicate.UserIpSubnetHistory {
	return []predicate.UserIpSubnetHistory{
		useripsubnethistory.HasUserWith(user.TenantID(p.TenantID)),
	}
}

func userPasswordHistoryScope(p *PrivacyContext) []predicate.UserPasswordHistory {
	return []predicate.UserPasswordHistory{
		userpasswordhistory.HasUserWith(user.TenantID(p.TenantID)),
	}
}
