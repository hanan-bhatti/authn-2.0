/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/repository.go
 * Tier: Internal Feature Package / Policy Repository
 *
 * Persistence for tenant policies, stored as JSON columns on the tenant record.
 *
 * Reads never fail the caller: a missing tenant, an absent column, or a value
 * that no longer parses all yield the documented defaults. A policy lookup sits
 * on the login and recovery paths, and a policy the engine cannot read must
 * degrade to the safe default rather than take authentication down with it.
 * Writes are the opposite — they validate, clamp, and report failure — because
 * that is the one moment a bad policy can still be refused.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// ErrTenantNotFound reports a policy write against a tenant that was never
// provisioned.
//
// Writing a policy used to create the tenant, which meant a typo in a tenant ID
// produced a workspace with no roles, no application and no owner. Tenants are
// created deliberately, so the write is refused instead.
var ErrTenantNotFound = errors.New("tenant not found")

// policyPoolEnvironment is the environment passed when selecting a connection
// pool for policy queries.
//
// Policies hang off the tenant record and are not environment-scoped: the
// privacy interceptor narrows a tenant query by tenant ID alone, so no policy
// row is reachable from one environment and hidden from another. The value here
// therefore selects a connection pool and nothing else, and since nothing
// registers a per-tenant pool it resolves to the shared default client — see
// clientfactory.ClientFactory.
//
// It is a fixed literal rather than the caller's environment because threading
// one through eight repository methods and their callers would pass a value that
// is discarded. If dedicated pools are ever registered, this constant becomes
// live and wrong — policy reads would land on whichever database "test" names —
// so that change and this line have to move together.
const policyPoolEnvironment = "test"

// Repository reads and writes tenant policies.
type Repository struct {
	// factory produces the ORM client for the tenant being read or written.
	factory *clientfactory.ClientFactory
}

// NewRepository returns a policy repository backed by the given client factory.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// GetPasswordPolicy returns the tenant's password policy, or
// DefaultPasswordPolicy when the tenant is missing, has none stored, or has one
// that no longer parses. Stored values are floored and capped on the way out, so
// a policy weakened below the engine's own minimum cannot take effect. The error
// is always nil.
func (r *Repository) GetPasswordPolicy(ctx context.Context, tenantID string) (PasswordPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return DefaultPasswordPolicy(), nil
	}

	if len(t.PasswordPolicy) == 0 {
		return DefaultPasswordPolicy(), nil
	}

	data, err := json.Marshal(t.PasswordPolicy)
	if err != nil {
		return DefaultPasswordPolicy(), nil
	}

	var p PasswordPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return DefaultPasswordPolicy(), nil
	}

	if p.MinLength < 6 {
		p.MinLength = 6
	}
	if p.MaxLength <= 0 || p.MaxLength > 4096 {
		p.MaxLength = 4096
	}
	if p.EnforcementMode == "" {
		p.EnforcementMode = "require"
	}

	return p, nil
}

// UpdatePasswordPolicy clamps the policy into range, persists it, and returns
// what was stored, creating the tenant record if it does not yet exist. Lengths
// outside the permitted range and an unrecognised enforcement mode are corrected
// rather than rejected. It returns an error only when the write fails.
func (r *Repository) UpdatePasswordPolicy(ctx context.Context, tenantID string, p PasswordPolicy) (PasswordPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)

	if p.MinLength < 6 {
		p.MinLength = 6
	}
	if p.MaxLength < p.MinLength || p.MaxLength > 4096 {
		p.MaxLength = 4096
	}
	if p.EnforcementMode != "require" && p.EnforcementMode != "notify" {
		p.EnforcementMode = "require"
	}

	var policyMap map[string]interface{}
	data, _ := json.Marshal(p)
	_ = json.Unmarshal(data, &policyMap)

	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(ctx)
	if err != nil {
		return p, fmt.Errorf("failed checking tenant existence: %w", err)
	}
	if !exists {
		return p, ErrTenantNotFound
	}

	if _, err = client.Tenant.UpdateOneID(tenantID).
		SetPasswordPolicy(policyMap).
		Save(ctx); err != nil {
		return p, fmt.Errorf("failed updating tenant password policy: %w", err)
	}

	return p, nil
}

// GetSecurityPolicy returns the tenant's security policy, or
// DefaultSecurityPolicy when the tenant is missing, has none stored, or has one
// that no longer parses. Unrecognised enum values are corrected to their
// defaults. The error is always nil.
func (r *Repository) GetSecurityPolicy(ctx context.Context, tenantID string) (SecurityPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return DefaultSecurityPolicy(), nil
	}

	if len(t.SecurityPolicy) == 0 {
		return DefaultSecurityPolicy(), nil
	}

	data, err := json.Marshal(t.SecurityPolicy)
	if err != nil {
		return DefaultSecurityPolicy(), nil
	}

	var sp SecurityPolicy
	if err := json.Unmarshal(data, &sp); err != nil {
		return DefaultSecurityPolicy(), nil
	}

	if sp.EmailVerificationMode != "hard" && sp.EmailVerificationMode != "soft" {
		sp.EmailVerificationMode = "soft"
	}
	if sp.TokenReusePolicy != "global_revoke" && sp.TokenReusePolicy != "session_revoke" {
		sp.TokenReusePolicy = "global_revoke"
	}

	return sp, nil
}

// UpdateSecurityPolicy corrects unrecognised enum values, persists the policy,
// and returns what was stored, creating the tenant record if it does not yet
// exist. It returns an error only when the write fails.
func (r *Repository) UpdateSecurityPolicy(ctx context.Context, tenantID string, sp SecurityPolicy) (SecurityPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)

	if sp.EmailVerificationMode != "hard" && sp.EmailVerificationMode != "soft" {
		sp.EmailVerificationMode = "soft"
	}
	if sp.TokenReusePolicy != "global_revoke" && sp.TokenReusePolicy != "session_revoke" {
		sp.TokenReusePolicy = "global_revoke"
	}

	var policyMap map[string]interface{}
	data, _ := json.Marshal(sp)
	_ = json.Unmarshal(data, &policyMap)

	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(ctx)
	if err != nil {
		return sp, fmt.Errorf("failed checking tenant existence: %w", err)
	}
	if !exists {
		return sp, ErrTenantNotFound
	}

	if _, err = client.Tenant.UpdateOneID(tenantID).
		SetSecurityPolicy(policyMap).
		Save(ctx); err != nil {
		return sp, fmt.Errorf("failed updating tenant security policy: %w", err)
	}

	return sp, nil
}

// GetRecoveryPolicy returns the tenant's recovery policy, or
// DefaultRecoveryPolicy when the tenant is missing, has none stored, or has one
// that no longer parses. The error is always nil.
func (r *Repository) GetRecoveryPolicy(ctx context.Context, tenantID string) (RecoveryPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return DefaultRecoveryPolicy(), nil
	}

	if len(t.RecoveryPolicy) == 0 {
		return DefaultRecoveryPolicy(), nil
	}

	data, err := json.Marshal(t.RecoveryPolicy)
	if err != nil {
		return DefaultRecoveryPolicy(), nil
	}

	var rp RecoveryPolicy
	if err := json.Unmarshal(data, &rp); err != nil {
		return DefaultRecoveryPolicy(), nil
	}

	return rp, nil
}

// UpdateRecoveryPolicy validates the policy in full before persisting it and
// returns what was stored, creating the tenant record if it does not yet exist.
//
// Unlike the password and security policies, nothing here is clamped: a recovery
// policy's fields constrain each other — schedule ordering, guardian bounds,
// method toggles — so an out-of-range value is refused rather than silently
// adjusted into a policy the caller did not ask for. It returns the validation
// error or the write error.
func (r *Repository) UpdateRecoveryPolicy(ctx context.Context, tenantID string, rp RecoveryPolicy) (RecoveryPolicy, error) {
	if err := ValidateRecoveryPolicy(rp); err != nil {
		return rp, fmt.Errorf("invalid recovery policy: %w", err)
	}

	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)

	var policyMap map[string]interface{}
	data, _ := json.Marshal(rp)
	_ = json.Unmarshal(data, &policyMap)

	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(ctx)
	if err != nil {
		return rp, fmt.Errorf("failed checking tenant existence: %w", err)
	}
	if !exists {
		return rp, ErrTenantNotFound
	}

	if _, err = client.Tenant.UpdateOneID(tenantID).
		SetRecoveryPolicy(policyMap).
		Save(ctx); err != nil {
		return rp, fmt.Errorf("failed updating tenant recovery policy: %w", err)
	}

	return rp, nil
}

// GetImpersonationPolicy returns the tenant's impersonation policy, nested under
// the security policy column, or DefaultImpersonationPolicy when the tenant is
// missing, the key is absent, the value does not parse, or the stored policy no
// longer validates.
//
// Re-validating on read matters: bounds can tighten between releases, and a
// policy stored under looser rules must not keep granting a longer session than
// the current rules permit. The error is always nil.
func (r *Repository) GetImpersonationPolicy(ctx context.Context, tenantID string) (ImpersonationPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil || t == nil || t.SecurityPolicy == nil {
		return DefaultImpersonationPolicy(), nil
	}

	raw, ok := t.SecurityPolicy["impersonation_policy"]
	if !ok || raw == nil {
		return DefaultImpersonationPolicy(), nil
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return DefaultImpersonationPolicy(), nil
	}

	var ip ImpersonationPolicy
	if err := json.Unmarshal(data, &ip); err != nil {
		return DefaultImpersonationPolicy(), nil
	}

	if err := ValidateImpersonationPolicy(ip); err != nil {
		return DefaultImpersonationPolicy(), nil
	}

	return ip, nil
}

// UpdateImpersonationPolicy validates the policy and merges it into the tenant's
// security policy column, preserving the column's other keys, and returns what
// was stored. It returns the validation error, an error when the tenant does not
// exist, or the write error. Unlike the other policies it does not create a
// tenant: an impersonation policy for a tenant that does not exist governs
// nothing.
func (r *Repository) UpdateImpersonationPolicy(ctx context.Context, tenantID string, ip ImpersonationPolicy) (ImpersonationPolicy, error) {
	if err := ValidateImpersonationPolicy(ip); err != nil {
		return ip, fmt.Errorf("invalid impersonation policy: %w", err)
	}

	client := r.factory.GetClient(ctx, tenantID, policyPoolEnvironment)
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return ip, fmt.Errorf("failed fetching tenant: %w", err)
	}

	secMap := t.SecurityPolicy
	if secMap == nil {
		secMap = make(map[string]interface{})
	}

	var policyMap map[string]interface{}
	data, _ := json.Marshal(ip)
	_ = json.Unmarshal(data, &policyMap)
	secMap["impersonation_policy"] = policyMap

	_, err = client.Tenant.UpdateOneID(tenantID).
		SetSecurityPolicy(secMap).
		Save(ctx)
	if err != nil {
		return ip, fmt.Errorf("failed updating tenant impersonation policy: %w", err)
	}

	return ip, nil
}
