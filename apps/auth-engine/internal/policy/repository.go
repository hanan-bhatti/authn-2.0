/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/repository.go
 * Tier: Internal Feature Package / Policy Repository
 *
 * Description: Data access layer for tenant password policies. Persists policy configurations
 *              in the Tenant ORM entity JSON field.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// Repository handles database queries and updates for password policies.
type Repository struct {
	factory *clientfactory.ClientFactory
}

// NewRepository constructs a new Policy Repository instance.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// GetPasswordPolicy retrieves the tenant's password policy, defaulting if unconfigured.
func (r *Repository) GetPasswordPolicy(ctx context.Context, tenantID string) (PasswordPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		// If tenant is missing, return default policy
		return DefaultPasswordPolicy(), nil
	}

	if t.PasswordPolicy == nil || len(t.PasswordPolicy) == 0 {
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

// UpdatePasswordPolicy updates and persists a tenant's password policy.
func (r *Repository) UpdatePasswordPolicy(ctx context.Context, tenantID string, p PasswordPolicy) (PasswordPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")

	// Validate min/max boundaries
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

	// Ensure tenant exists
	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(ctx)
	if err != nil {
		return p, fmt.Errorf("failed checking tenant existence: %w", err)
	}

	if !exists {
		_, err = client.Tenant.Create().
			SetID(tenantID).
			SetName("Default Workspace").
			SetSlug(tenantID).
			SetPasswordPolicy(policyMap).
			Save(ctx)
		if err != nil {
			return p, fmt.Errorf("failed creating tenant with password policy: %w", err)
		}
	} else {
		_, err = client.Tenant.UpdateOneID(tenantID).
			SetPasswordPolicy(policyMap).
			Save(ctx)
		if err != nil {
			return p, fmt.Errorf("failed updating tenant password policy: %w", err)
		}
	}

	return p, nil
}

// GetSecurityPolicy retrieves the tenant's security policy, defaulting if unconfigured.
func (r *Repository) GetSecurityPolicy(ctx context.Context, tenantID string) (SecurityPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return DefaultSecurityPolicy(), nil
	}

	if t.SecurityPolicy == nil || len(t.SecurityPolicy) == 0 {
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

// UpdateSecurityPolicy updates and persists a tenant's security policy.
func (r *Repository) UpdateSecurityPolicy(ctx context.Context, tenantID string, sp SecurityPolicy) (SecurityPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")

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
		_, err = client.Tenant.Create().
			SetID(tenantID).
			SetName("Default Workspace").
			SetSlug(tenantID).
			SetSecurityPolicy(policyMap).
			Save(ctx)
		if err != nil {
			return sp, fmt.Errorf("failed creating tenant with security policy: %w", err)
		}
	} else {
		_, err = client.Tenant.UpdateOneID(tenantID).
			SetSecurityPolicy(policyMap).
			Save(ctx)
		if err != nil {
			return sp, fmt.Errorf("failed updating tenant security policy: %w", err)
		}
	}

	return sp, nil
}

// GetRecoveryPolicy retrieves the tenant's account recovery policy, defaulting if unconfigured.
func (r *Repository) GetRecoveryPolicy(ctx context.Context, tenantID string) (RecoveryPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")
	t, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return DefaultRecoveryPolicy(), nil
	}

	if t.RecoveryPolicy == nil || len(t.RecoveryPolicy) == 0 {
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

// UpdateRecoveryPolicy validates and persists a tenant's account recovery policy.
func (r *Repository) UpdateRecoveryPolicy(ctx context.Context, tenantID string, rp RecoveryPolicy) (RecoveryPolicy, error) {
	// Execute strict 9-rule policy validation before saving
	if err := ValidateRecoveryPolicy(rp); err != nil {
		return rp, fmt.Errorf("invalid recovery policy: %w", err)
	}

	client := r.factory.GetClient(ctx, tenantID, "test")

	var policyMap map[string]interface{}
	data, _ := json.Marshal(rp)
	_ = json.Unmarshal(data, &policyMap)

	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(ctx)
	if err != nil {
		return rp, fmt.Errorf("failed checking tenant existence: %w", err)
	}

	if !exists {
		_, err = client.Tenant.Create().
			SetID(tenantID).
			SetName("Default Workspace").
			SetSlug(tenantID).
			SetRecoveryPolicy(policyMap).
			Save(ctx)
		if err != nil {
			return rp, fmt.Errorf("failed creating tenant with recovery policy: %w", err)
		}
	} else {
		_, err = client.Tenant.UpdateOneID(tenantID).
			SetRecoveryPolicy(policyMap).
			Save(ctx)
		if err != nil {
			return rp, fmt.Errorf("failed updating tenant recovery policy: %w", err)
		}
	}

	return rp, nil
}

// GetImpersonationPolicy retrieves the tenant's impersonation policy, defaulting if unconfigured.
func (r *Repository) GetImpersonationPolicy(ctx context.Context, tenantID string) (ImpersonationPolicy, error) {
	client := r.factory.GetClient(ctx, tenantID, "test")
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

// UpdateImpersonationPolicy validates and persists a tenant's impersonation policy.
func (r *Repository) UpdateImpersonationPolicy(ctx context.Context, tenantID string, ip ImpersonationPolicy) (ImpersonationPolicy, error) {
	if err := ValidateImpersonationPolicy(ip); err != nil {
		return ip, fmt.Errorf("invalid impersonation policy: %w", err)
	}

	client := r.factory.GetClient(ctx, tenantID, "test")
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
