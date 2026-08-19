/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/provisioning/provisioning.go
 * Tier: Internal Feature Package / Tenant Provisioning
 *
 * Creates a tenant and everything it needs to be usable.
 *
 * A tenant is not one row. A tenant nobody can authenticate against, with no
 * roles for its administrator to hold, is indistinguishable from a broken one.
 * Provisioning is therefore a single operation that yields a tenant, an
 * application, one key pair and the system roles together, so no caller can end
 * up holding a half-built one.
 *
 * Everything here runs under a privacy bypass, for the same reason the API key
 * lookup does: the tenant being created is what a scoped query would filter by,
 * so no scoped query could match it. The bypass is confined to this package,
 * and callers receive plain data rather than a bypassed context.
 *
 * This is the one path both front doors use — cmd/bootstrap for self-hosters,
 * and the platform provisioning API for the hosted product — so the two cannot
 * drift into producing differently-shaped tenants.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package provisioning

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/apikey"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

// Errors returned by Provision. Callers map these onto their own surface: the
// CLI prints them, the HTTP handler turns them into 4xx responses.
var (
	// ErrInvalidName reports a missing or unusable tenant name.
	ErrInvalidName = errors.New("tenant name is required")
	// ErrInvalidSlug reports a slug that cannot be derived or does not conform.
	ErrInvalidSlug = errors.New("tenant slug must be 3-63 characters of lowercase letters, digits and hyphens")
	// ErrReservedSlug reports an attempt to claim a slug the platform reserves.
	//
	// This is load-bearing rather than cosmetic: provisioning is idempotent by
	// slug, so without this guard a caller naming the platform's own slug would
	// not create a tenant — the existing control-plane tenant would be returned,
	// along with a freshly minted secret key for it.
	ErrReservedSlug = errors.New("that tenant slug is reserved")
	// ErrInvalidEnvironment reports an environment other than test or live.
	ErrInvalidEnvironment = errors.New("environment must be \"test\" or \"live\"")
)

// reservedSlugs are refused for customer tenants regardless of configuration.
//
// The configured platform slug is refused too, via Options.ReservedSlugs; this
// list covers names that would be confusing or dangerous in any deployment.
var reservedSlugs = map[string]struct{}{
	"platform": {}, "admin": {}, "system": {}, "default": {},
	"internal": {}, "authn": {}, "console": {}, "api": {}, "www": {},
}

// slugPattern is the accepted slug shape: lowercase alphanumerics and interior
// hyphens. It doubles as the tenant's URL identity, so it is deliberately
// narrower than the database's uniqueness constraint alone would require.
var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

const (
	// minSlugLength and maxSlugLength bound the slug. The upper bound is the DNS
	// label limit, so a slug can always be used as a subdomain later.
	minSlugLength = 3
	maxSlugLength = 63

	// envTest and envLive are the two environments an application and its keys
	// can belong to. They mirror the enum on the Application and ApiKey schemas.
	envTest = "test"
	envLive = "live"
)

// Request describes the tenant to create.
type Request struct {
	// Name is the human-readable organization name. Required.
	Name string
	// Slug is the URL-friendly identifier. Derived from Name when empty.
	Slug string
	// Environment is "test" or "live" for the first application and its keys.
	// Defaults to "test", which is the safer default for a first key pair.
	Environment string
	// ApplicationName labels the first application. Defaults to "Default".
	ApplicationName string
	// RedirectURIs is the initial exact-match allowlist for the application.
	RedirectURIs []string
	// AllowedCorsOrigins is the initial browser-origin allowlist. An empty list
	// means "not configured" and leaves origin checking to the deployment-wide
	// policy.
	AllowedCorsOrigins []string
}

// Options adjusts provisioning for callers with different authority.
//
// The zero value is the customer-facing behavior: reserved slugs refused, both
// keys minted, first-admin slot open. Only trusted internal callers — the
// bootstrap CLI creating the platform tenant, and the seeder pinning its demo
// identifiers — set these.
type Options struct {
	// TenantID pins the tenant's identifier instead of generating one. The
	// seeder needs this to keep producing tnt_default.
	TenantID string
	// ApplicationID pins the application's identifier.
	ApplicationID string
	// ReservedSlugs are additional slugs to refuse, beyond the built-in list.
	// The platform tenant's own slug belongs here.
	ReservedSlugs []string
	// AllowReservedSlug permits claiming a reserved slug. Set only when creating
	// the platform tenant itself.
	AllowReservedSlug bool
	// SkipKeys suppresses key generation. The seeder installs its own fixed demo
	// keys afterwards.
	SkipKeys bool
	// SkipSecretKey mints only the publishable key.
	//
	// Used for the platform tenant, which is reached exclusively by JWT: a
	// secret key for the control plane would grant its admin surface to whoever
	// held it, and a key that is never minted cannot leak.
	SkipSecretKey bool
	// ClaimFirstAdmin marks the first-admin slot as already taken.
	//
	// Set for the platform tenant, whose publishable key ships in the console's
	// browser bundle: without it, the first stranger to sign up on the console
	// would be granted tenant_admin over the control plane.
	ClaimFirstAdmin bool
}

// Result reports what was provisioned.
type Result struct {
	// TenantID and TenantSlug identify the tenant.
	TenantID   string
	TenantSlug string
	// TenantName is the stored display name.
	TenantName string
	// ApplicationID is the first application.
	ApplicationID string
	// Environment is the environment the application and keys were created in.
	Environment string
	// PublishableKey and SecretKey are the raw credentials. This is the only
	// time they exist in readable form; only their hashes are stored. Either may
	// be empty when suppressed by Options.
	PublishableKey string
	SecretKey      string
	// AlreadyExisted reports that a tenant with this slug was already present,
	// in which case no new keys were minted and the key fields are empty.
	AlreadyExisted bool
	// RolesInstalled counts the system roles present afterwards.
	RolesInstalled int
}

// Provision creates a tenant, its first application, an API key pair and the
// system roles, and returns the raw keys.
//
// It is idempotent by slug: provisioning twice with the same slug yields the
// existing tenant with AlreadyExisted set and no new keys, rather than a second
// tenant or an error. That makes it safe to call from a container entrypoint
// that may restart.
//
// The tenant's first-admin slot is left open, so the first person to sign up
// through the returned publishable key atomically becomes its tenant_admin via
// the existing ClaimFirstAdminRole path — unless Options.ClaimFirstAdmin closes
// it, which the platform tenant requires.
//
// Returns ErrInvalidName, ErrInvalidSlug, ErrReservedSlug or
// ErrInvalidEnvironment for bad input, and a wrapped storage error otherwise.
// A failure partway through leaves whatever was already committed; re-running
// with the same slug completes the remainder rather than duplicating it.
func (s *Service) Provision(ctx context.Context, req Request, opts Options) (*Result, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, ErrInvalidName
	}

	slug := strings.TrimSpace(strings.ToLower(req.Slug))
	if slug == "" {
		slug = Slugify(name)
	}
	if err := validateSlug(slug); err != nil {
		return nil, err
	}
	if !opts.AllowReservedSlug && isReserved(slug, opts.ReservedSlugs) {
		return nil, ErrReservedSlug
	}

	env := strings.TrimSpace(strings.ToLower(req.Environment))
	if env == "" {
		env = envTest
	}
	if env != envTest && env != envLive {
		return nil, ErrInvalidEnvironment
	}

	// An existing slug short-circuits before anything is written, so a repeated
	// call neither mints new credentials nor disturbs the tenant it finds.
	existing, err := s.repo.FindTenantBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		roles, err := s.repo.EnsureSystemRoles(ctx, existing.ID)
		if err != nil {
			return nil, err
		}
		// Settings rows are ensured on the repeat path too, so a tenant provisioned
		// before the two environments existed acquires them on the next call rather
		// than waiting for somebody to change a setting.
		if err := s.repo.EnsureEnvironments(ctx, existing.ID); err != nil {
			return nil, err
		}
		return &Result{
			TenantID:       existing.ID,
			TenantSlug:     existing.Slug,
			TenantName:     existing.Name,
			Environment:    env,
			AlreadyExisted: true,
			RolesInstalled: roles,
		}, nil
	}

	tenantID := opts.TenantID
	if tenantID == "" {
		tenantID = idgen.New("tnt")
	}
	appID := opts.ApplicationID
	if appID == "" {
		appID = idgen.New("app")
	}
	appName := strings.TrimSpace(req.ApplicationName)
	if appName == "" {
		appName = "Default"
	}

	if err := s.repo.CreateTenant(ctx, tenantID, name, slug, opts.ClaimFirstAdmin); err != nil {
		return nil, err
	}
	if err := s.repo.CreateApplication(ctx, appID, tenantID, appName, env,
		req.RedirectURIs, req.AllowedCorsOrigins); err != nil {
		return nil, err
	}

	roles, err := s.repo.EnsureSystemRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	result := &Result{
		TenantID:       tenantID,
		TenantSlug:     slug,
		TenantName:     name,
		ApplicationID:  appID,
		Environment:    env,
		RolesInstalled: roles,
	}

	if opts.SkipKeys {
		return result, nil
	}

	pk, err := s.keys.CreateKey(ctx, "", appID, appName+" publishable", apikey.TypePublishable, env, nil)
	if err != nil {
		return nil, fmt.Errorf("minting publishable key for tenant %s: %w", tenantID, err)
	}
	result.PublishableKey = pk.RawKey

	if !opts.SkipSecretKey {
		sk, err := s.keys.CreateKey(ctx, "", appID, appName+" secret", apikey.TypeSecret, env, nil)
		if err != nil {
			return nil, fmt.Errorf("minting secret key for tenant %s: %w", tenantID, err)
		}
		result.SecretKey = sk.RawKey
	}

	return result, nil
}

// Slugify derives a URL-friendly slug from a display name.
//
// Runs of anything outside [a-z0-9] collapse to a single hyphen, and the result
// is trimmed to the maximum length on a hyphen boundary so it does not end mid-
// word. The output may still be invalid — an all-punctuation name yields an
// empty string — so callers must pass it through validateSlug.
func Slugify(name string) string {
	var b strings.Builder
	lastHyphen := true // leading hyphens are suppressed
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastHyphen = false
		case !lastHyphen:
			b.WriteByte('-')
			lastHyphen = true
		}
	}

	slug := strings.Trim(b.String(), "-")
	if len(slug) > maxSlugLength {
		slug = slug[:maxSlugLength]
		if i := strings.LastIndexByte(slug, '-'); i > minSlugLength {
			slug = slug[:i]
		}
		slug = strings.Trim(slug, "-")
	}
	return slug
}

// validateSlug reports whether slug is a usable tenant identifier.
func validateSlug(slug string) error {
	if len(slug) < minSlugLength || len(slug) > maxSlugLength || !slugPattern.MatchString(slug) {
		return fmt.Errorf("%w: got %q", ErrInvalidSlug, slug)
	}
	return nil
}

// isReserved reports whether slug is refused, checking both the built-in list
// and the deployment's configured additions.
func isReserved(slug string, extra []string) bool {
	if _, found := reservedSlugs[slug]; found {
		return true
	}
	for _, s := range extra {
		if strings.EqualFold(strings.TrimSpace(s), slug) {
			return true
		}
	}
	return false
}
