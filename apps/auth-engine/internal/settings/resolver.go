/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/settings/resolver.go
 * Tier: Internal Feature Package / Runtime Settings Resolution
 *
 * Reads the settings a customer can change at runtime, with a cache in front.
 *
 * The rule this package exists to serve: anything a customer changes lives in the
 * database and takes effect immediately, and only what the deployment itself is
 * bound to lives in the environment. Requiring a redeploy to add one CORS origin
 * is not workable once there are real customers, and a restart is downtime.
 *
 * That rule puts row reads on the request path, so a cache is not optional. Two
 * things are cached: an application's settings by application ID, and a tenant's
 * session policy by tenant ID. Both have a short TTL, and both are invalidated on
 * write, so a settings change is effectively immediate rather than eventually
 * visible.
 *
 * Redis is a cache here and never the system of record. A Redis outage degrades
 * to reading the row directly — slower, still correct — because authentication
 * must not depend on the cache being up. See docs/ARCHITECTURE-DEGRADED-MODE.md.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package settings

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

const (
	// DefaultTTL is how long a cached settings entry is trusted.
	//
	// Short enough that a change nobody invalidated still lands within a minute
	// — a second engine replica writes its own invalidation, but a row edited
	// directly in the database has nothing to publish one. Long enough that a
	// busy tenant is not re-reading the same row on every request.
	DefaultTTL = 45 * time.Second

	// appKeyPrefix and tenantKeyPrefix namespace the cache entries. The
	// application entry is keyed by application ID and the policy entry by
	// tenant ID and environment together, matching what each caller has in hand at
	// the point of use.
	//
	// The environment belongs in the policy key because a tenant has one session
	// policy per environment. Keyed by tenant alone, whichever environment read
	// first would answer for both, and a live sign-in would silently run on the
	// sandbox's token lifetimes.
	appKeyPrefix    = "settings:app:"
	tenantKeyPrefix = "settings:session_policy:"

	// cacheOpTimeout bounds a single cache operation. A cache that has become
	// slow must not make every request slow: past this, the row read wins.
	cacheOpTimeout = 150 * time.Millisecond
)

// Application is an application's runtime-changeable settings.
//
// It is a plain struct rather than the Ent entity because it is what gets cached:
// a stable JSON shape that does not change when an unrelated column is added to
// the table.
type Application struct {
	// ID is the application's identifier, and the cache key.
	ID string `json:"id"`
	// TenantID is the owning tenant. Cached alongside the rest because a caller
	// resolving an application almost always needs to scope by its tenant next.
	TenantID string `json:"tenant_id"`
	// Name is the human-readable application name.
	Name string `json:"name"`
	// Environment is "test" or "live".
	Environment string `json:"environment"`
	// AllowedCorsOrigins is the browser-origin allowlist. Empty means "not
	// configured", which leaves origin checking to the deployment-wide policy.
	AllowedCorsOrigins []string `json:"allowed_cors_origins"`
	// ExactRedirectURIs is the OAuth redirect allowlist, matched exactly.
	ExactRedirectURIs []string `json:"exact_redirect_uris"`
	// FrontendBaseURL is the origin of this application's own UI, prefixed to
	// emailed link landings. Empty means the application has configured none and
	// the deployment default applies.
	FrontendBaseURL string `json:"frontend_base_url"`
}

// Resolver reads runtime settings, serving them from Redis when it can and from
// the database when it cannot.
type Resolver struct {
	// factory produces the ORM client for the row reads.
	factory *clientfactory.ClientFactory
	// policies reads the tenant policy columns. Its reads already degrade to
	// documented defaults, so this layer adds caching and nothing else.
	policies *policy.Repository
	// cache is the Redis client, or nil when the deployment runs without one.
	// Every use is nil-checked rather than requiring a null object, because a
	// nil client is the normal configuration for a single-node self-hoster.
	cache *redis.Client
	// ttl is how long an entry is trusted.
	ttl time.Duration
}

// NewResolver returns a Resolver. A nil cache is valid and means every read goes
// to the database; a zero ttl takes DefaultTTL.
func NewResolver(factory *clientfactory.ClientFactory, policies *policy.Repository, cache *redis.Client, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Resolver{factory: factory, policies: policies, cache: cache, ttl: ttl}
}

// SessionPolicy returns the tenant's session policy for one environment.
//
// It never fails: a cache miss falls through to the row, and an unreadable or
// unparseable row yields policy.DefaultSessionPolicy. This is called wherever a
// cookie is written, which includes the login and refresh paths, so a failure
// here would be a failure to sign in.
//
// An environment that names neither test nor live yields the defaults rather than
// an arbitrary environment's policy, so a caller that failed to resolve one cannot
// end up enforcing the other environment's token lifetimes.
func (r *Resolver) SessionPolicy(ctx context.Context, tenantID, environment string) policy.SessionPolicy {
	if tenantID == "" || !policy.ValidEnvironment(environment) {
		return policy.DefaultSessionPolicy()
	}

	key := sessionPolicyKey(tenantID, environment)
	var sp policy.SessionPolicy
	if r.getCached(ctx, key, &sp) {
		// Normalize on the way out of the cache too: an entry written by an older
		// build may predate a tightened bound.
		return policy.NormalizeSessionPolicy(sp)
	}

	if r.policies == nil {
		return policy.DefaultSessionPolicy()
	}

	sp, err := r.policies.GetSessionPolicy(ctx, tenantID, environment)
	if err != nil {
		return policy.DefaultSessionPolicy()
	}

	r.putCached(ctx, key, sp)
	return sp
}

// sessionPolicyKey is the cache key for one tenant's session policy in one
// environment.
func sessionPolicyKey(tenantID, environment string) string {
	return tenantKeyPrefix + tenantID + ":" + environment
}

// Application returns an application's settings by ID, or nil when no such
// application exists.
//
// The lookup runs under a privacy bypass for the same reason the API key lookup
// does: this is one of the reads that establishes tenancy, so a tenant-scoped
// query could not match the row that names the tenant. The bypass is confined to
// this function and callers receive plain data.
func (r *Resolver) Application(ctx context.Context, applicationID string) (*Application, error) {
	if applicationID == "" {
		return nil, nil
	}

	key := appKeyPrefix + applicationID
	var cached Application
	if r.getCached(ctx, key, &cached) {
		return &cached, nil
	}

	sysCtx := privacy.NewBypassContext(ctx)
	row, err := r.factory.GetClient(sysCtx, "", "").Application.Query().
		Where(application.ID(applicationID)).
		Only(sysCtx)
	if err != nil {
		// A missing application is not an error to the caller — it is the answer.
		// Distinguishing "absent" from "the database is down" matters, so only
		// the latter propagates.
		if ent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	resolved := &Application{
		ID:                 row.ID,
		TenantID:           row.TenantID,
		Name:               row.Name,
		Environment:        string(row.Environment),
		AllowedCorsOrigins: row.AllowedCorsOrigins,
		ExactRedirectURIs:  row.ExactRedirectUris,
		FrontendBaseURL:    row.FrontendBaseURL,
	}

	r.putCached(ctx, key, resolved)
	return resolved, nil
}

// FrontendBaseURL returns the origin an application's emailed links should point
// at, or "" when it has configured none.
//
// It reports only what the row says, leaving the deployment default to the
// caller: only the caller knows whether it is building a link at all, and a
// resolver that substituted a default would make "this application chose an
// origin" indistinguishable from "nobody has".
//
// Like SessionPolicy it never fails. An unreadable row or an absent application
// yields "", so a cache or database problem downgrades a link to the deployment
// default rather than failing the send that carries it.
func (r *Resolver) FrontendBaseURL(ctx context.Context, applicationID string) string {
	app, err := r.Application(ctx, applicationID)
	if err != nil || app == nil {
		return ""
	}
	return app.FrontendBaseURL
}

// InvalidateApplication drops an application's cached settings.
//
// Every write to an application's settings must call this, which is what makes a
// change effectively immediate rather than TTL-delayed. It is best-effort: a
// failed delete leaves an entry that expires on its own within the TTL.
func (r *Resolver) InvalidateApplication(ctx context.Context, applicationID string) {
	r.invalidate(ctx, appKeyPrefix+applicationID)
}

// InvalidateTenantPolicy drops a tenant's cached session policy for one
// environment. Called by every write to that policy, for the same reason as
// InvalidateApplication.
//
// Only the written environment is evicted: publishing test settings to live
// changes live's policy and not test's, and evicting both would throw away a
// perfectly current entry.
func (r *Resolver) InvalidateTenantPolicy(ctx context.Context, tenantID, environment string) {
	r.invalidate(ctx, sessionPolicyKey(tenantID, environment))
}

// getCached fills dst from the cache, reporting whether it succeeded.
//
// Every failure — no client, a timeout, a miss, or an entry that no longer
// unmarshals into dst — is reported the same way, as "not cached", so the caller
// falls through to the row. A cache is never allowed to turn into an error.
func (r *Resolver) getCached(ctx context.Context, key string, dst any) bool {
	if r.cache == nil {
		return false
	}

	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()

	raw, err := r.cache.Get(opCtx, key).Bytes()
	if err != nil || len(raw) == 0 {
		return false
	}
	return json.Unmarshal(raw, dst) == nil
}

// putCached stores v under key for the resolver's TTL, best-effort. A failure to
// cache costs a row read next time and nothing else, so it is not reported.
func (r *Resolver) putCached(ctx context.Context, key string, v any) {
	if r.cache == nil {
		return
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return
	}

	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	_ = r.cache.Set(opCtx, key, raw, r.ttl).Err()
}

// invalidate deletes key, best-effort.
func (r *Resolver) invalidate(ctx context.Context, key string) {
	if r.cache == nil {
		return
	}

	opCtx, cancel := context.WithTimeout(ctx, cacheOpTimeout)
	defer cancel()
	_ = r.cache.Del(opCtx, key).Err()
}
