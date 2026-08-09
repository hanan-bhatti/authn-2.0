/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/privacy/context.go
 * Tier: Security & Privacy Layer / Request Scope
 *
 * Carries the tenant, application and environment a request acts within, from
 * the middleware that authenticates it to the ORM interceptors that enforce it.
 *
 * The scope travels in the context rather than as a parameter so that no query
 * can be written without it. A repository method that forgets to filter by
 * tenant is not a leak here: the interceptor reads this value and applies the
 * filter itself, and refuses the query outright when the value is absent.
 *
 * The context key is an unexported empty struct, so nothing outside this
 * package can set or overwrite the scope. Code elsewhere must go through
 * NewContext, and a request cannot widen its own scope by writing a context
 * value directly.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package privacy

import (
	"context"
)

// privacyKey is the context key for the request scope. It is an unexported
// zero-size type, which both avoids collisions with other packages' keys and
// keeps the value unreachable from outside.
type privacyKey struct{}

// PrivacyContext is the tenant boundary a request operates inside.
type PrivacyContext struct {
	// TenantID is the tenant every query is confined to. Empty means unscoped,
	// which the interceptors reject unless Bypass is set.
	TenantID string
	// ApplicationID is the application the credential belongs to, recorded for
	// attribution. Queries are not filtered by it.
	ApplicationID string
	// Environment is "test" or "live". Empty leaves a query unfiltered by
	// environment, so it spans both — appropriate when resolving a credential
	// before its environment is known, and not otherwise.
	Environment string
	// Bypass disables every boundary check for this context.
	//
	// It exists for work that has no tenant by nature: schema migration,
	// seeding, and the credential lookup that determines which tenant a request
	// belongs to. Setting it on a request-derived context removes the isolation
	// between tenants entirely, so it belongs only in code paths that run
	// before or outside a request.
	Bypass bool
}

// NewContext returns a context scoped to a tenant, application and environment.
//
// This is what request middleware installs once a credential resolves. Bypass
// is explicitly false: a scope built from a request never disables the checks.
func NewContext(ctx context.Context, tenantID string, appID string, environment string) context.Context {
	return context.WithValue(ctx, privacyKey{}, &PrivacyContext{
		TenantID:      tenantID,
		ApplicationID: appID,
		Environment:   environment,
		Bypass:        false,
	})
}

// NewBypassContext returns a context with every tenant boundary check disabled.
//
// Reserved for system work that legitimately spans tenants — migration,
// seeding, and resolving which tenant a credential belongs to. Deriving one
// from a request context hands that request access to every tenant's data, so
// it must not be reachable from a request path except for that credential
// lookup, which is scoped to the lookup alone.
func NewBypassContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, privacyKey{}, &PrivacyContext{
		Bypass: true,
	})
}

// FromContext returns the scope carried by ctx.
//
// The boolean reports whether one is present at all, which is distinct from a
// scope present but empty. Interceptors treat both as unscoped and refuse the
// query, so a context that never passed through middleware fails closed rather
// than reading across tenants.
func FromContext(ctx context.Context) (*PrivacyContext, bool) {
	p, ok := ctx.Value(privacyKey{}).(*PrivacyContext)
	return p, ok
}
