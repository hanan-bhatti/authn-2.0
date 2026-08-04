/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/privacy/context.go
 * Tier: Security & Privacy Layer / Context Management
 *
 * Description: Defines request privacy context holding tenant_id, application_id,
 *              and environment mode for ORM-level tenant boundary isolation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package privacy

import (
	"context"
)

type privacyKey struct{}

// PrivacyContext holds the active tenant, application, and environment scope for a request context.
type PrivacyContext struct {
	TenantID      string
	ApplicationID string
	Environment   string
	Bypass        bool // Set to true strictly for internal system migrations or background bootstrap tasks
}

// NewContext injects a PrivacyContext into the given context.
func NewContext(ctx context.Context, tenantID string, appID string, environment string) context.Context {
	return context.WithValue(ctx, privacyKey{}, &PrivacyContext{
		TenantID:      tenantID,
		ApplicationID: appID,
		Environment:   environment,
		Bypass:        false,
	})
}

// NewBypassContext returns a context with privacy checks bypassed for system initialization tasks.
func NewBypassContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, privacyKey{}, &PrivacyContext{
		Bypass: true,
	})
}

// FromContext extracts the PrivacyContext from context.
func FromContext(ctx context.Context) (*PrivacyContext, bool) {
	p, ok := ctx.Value(privacyKey{}).(*PrivacyContext)
	return p, ok
}
