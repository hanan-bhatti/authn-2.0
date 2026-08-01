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
