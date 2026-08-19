/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/policy/repository.go
 * Tier: Internal Feature Package / Policy Repository
 *
 * Persistence for tenant policies, stored as JSON columns on the tenant's
 * per-environment settings row.
 *
 * Every policy is held once per environment, so a change can be rehearsed against
 * test sign-ins before it governs live ones. That makes the environment argument
 * part of a policy's identity rather than a routing detail: the same tenant has two
 * password policies, and reading the wrong one enforces rules the caller did not
 * configure.
 *
 * Reads never fail the caller: a missing tenant, a missing settings row, an absent
 * column, or a value that no longer parses all yield the documented defaults. A
 * policy lookup sits on the login and recovery paths, and a policy the engine
 * cannot read must degrade to the safe default rather than take authentication
 * down with it. Writes are the opposite — they validate, clamp, and report failure
 * — because that is the one moment a bad policy can still be refused.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenant"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/tenantenvironment"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

// ErrTenantNotFound reports a policy write against a tenant that was never
// provisioned.
//
// A policy write never creates the tenant it addresses. Tenants are created
// deliberately, with roles, an application and an owner; conjuring one from a
// mistyped identifier would produce a workspace holding none of those. The
// per-environment settings row is different and is created on demand, because it
// holds nothing but the policy being written.
var ErrTenantNotFound = errors.New("tenant not found")

// ErrInvalidEnvironment reports a policy operation naming neither environment.
//
// Refused rather than defaulted. Guessing would write a policy into whichever
// environment the guess named, and a policy applied to the wrong environment is
// indistinguishable from one that failed to apply.
var ErrInvalidEnvironment = errors.New("environment must be \"test\" or \"live\"")

// ErrTenantMismatch reports a policy operation on a tenant other than the one the
// calling request is confined to.
//
// The tenant is taken from the request scope and the environment from the argument,
// so a caller may read either of its own environments but neither of anyone else's.
var ErrTenantMismatch = errors.New("policy request crosses the caller's tenant boundary")

// settingsField names one of the JSON columns holding a policy.
//
// A private type over private constants, so the only values reaching the setters
// below are the ones defined here.
type settingsField string

const (
	fieldBrandingConfig settingsField = "branding_config"
	fieldPasswordPolicy settingsField = "password_policy"
	fieldSecurityPolicy settingsField = "security_policy"
	fieldRecoveryPolicy settingsField = "recovery_policy"
	fieldSocialProvider settingsField = "social_providers"
	fieldRolePolicy     settingsField = "role_policy"
	fieldSessionPolicy  settingsField = "session_policy"
)

// Settings is a verbatim copy of one environment's policy columns.
//
// The values stay as raw maps rather than the typed policy structs because this is
// what publishing copies and what a diff preview compares. Decoding into the typed
// structs and re-encoding would drop any key the current build does not know about,
// which would make publishing quietly lossy for a policy written by a newer engine.
type Settings struct {
	BrandingConfig  map[string]interface{} `json:"branding_config"`
	PasswordPolicy  map[string]interface{} `json:"password_policy"`
	SecurityPolicy  map[string]interface{} `json:"security_policy"`
	RecoveryPolicy  map[string]interface{} `json:"recovery_policy"`
	SocialProviders map[string]interface{} `json:"social_providers"`
	RolePolicy      map[string]interface{} `json:"role_policy"`
	SessionPolicy   map[string]interface{} `json:"session_policy"`
}

// Repository reads and writes tenant policies.
type Repository struct {
	// factory produces the ORM client for the tenant being read or written.
	factory *clientfactory.ClientFactory
}

// NewRepository returns a policy repository backed by the given client factory.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// ValidEnvironment reports whether environment names one of the two environments.
func ValidEnvironment(environment string) bool {
	return environment == string(tenantenvironment.EnvironmentTest) ||
		environment == string(tenantenvironment.EnvironmentLive)
}

// scopeFor returns a context whose privacy scope names the environment being read
// or written, and reports a mismatch when the caller is confined to another tenant.
//
// The environment has to be imposed here rather than inherited, and that is the
// whole reason this function exists. A request authenticated with a live key
// carries a live-scoped context; if that scope reached the interceptor unchanged,
// asking for the test password policy would AND "environment = live" onto a query
// for the test row, match nothing, and return the documented defaults. The caller
// would receive a plausible policy that is not the stored one — and publishing
// test settings to live would copy those defaults over the customer's real
// configuration.
//
// The tenant is taken from the scope rather than the argument, so widening is not
// possible: an absent scope is left absent and the interceptor refuses the query,
// and a scope naming a different tenant is an error rather than a silent switch.
func (r *Repository) scopeFor(ctx context.Context, tenantID, environment string) (context.Context, error) {
	p, ok := privacy.FromContext(ctx)
	switch {
	case !ok:
		// Nothing to narrow and nothing to trust. Left as-is so the interceptor
		// refuses, keeping a context that never passed through middleware failing
		// closed rather than being handed a scope by this layer.
		return ctx, nil
	case p.Bypass:
		// Provisioning and seeding legitimately span tenants. The explicit
		// predicates on every query below still select exactly one row.
		return ctx, nil
	case p.TenantID != tenantID:
		return nil, fmt.Errorf("%w: settings for tenant %q requested under a scope for tenant %q",
			ErrTenantMismatch, tenantID, p.TenantID)
	default:
		return privacy.NewContext(ctx, tenantID, p.ApplicationID, environment), nil
	}
}

// row returns the tenant's settings row for one environment.
//
// Both columns are constrained explicitly as well as by the interceptor, so the
// query selects a single row under a bypass context too, where the interceptor adds
// nothing.
func (r *Repository) row(ctx context.Context, tenantID, environment string) (*ent.TenantEnvironment, error) {
	if !ValidEnvironment(environment) {
		return nil, ErrInvalidEnvironment
	}

	scoped, err := r.scopeFor(ctx, tenantID, environment)
	if err != nil {
		return nil, err
	}

	return r.factory.GetClient(scoped, tenantID, environment).TenantEnvironment.Query().
		Where(
			tenantenvironment.TenantID(tenantID),
			tenantenvironment.EnvironmentEQ(tenantenvironment.Environment(environment)),
		).
		Only(scoped)
}

// blob returns one policy column, or nil when it cannot be read for any reason.
//
// Every failure collapses to nil because every caller of this treats "no stored
// policy" and "unreadable policy" the same way: return the documented default. A
// read on the login path has nothing useful to do with the distinction.
func (r *Repository) blob(ctx context.Context, tenantID, environment string, f settingsField) map[string]interface{} {
	row, err := r.row(ctx, tenantID, environment)
	if err != nil || row == nil {
		return nil
	}

	switch f {
	case fieldBrandingConfig:
		return row.BrandingConfig
	case fieldPasswordPolicy:
		return row.PasswordPolicy
	case fieldSecurityPolicy:
		return row.SecurityPolicy
	case fieldRecoveryPolicy:
		return row.RecoveryPolicy
	case fieldSocialProvider:
		return row.SocialProviders
	case fieldRolePolicy:
		return row.RolePolicy
	case fieldSessionPolicy:
		return row.SessionPolicy
	}
	return nil
}

// putBlob writes one policy column, creating the settings row when the tenant has
// none for this environment yet.
//
// The tenant itself must already exist; the settings row need not, because it holds
// only policy and a tenant with no stored policy is running on the defaults.
func (r *Repository) putBlob(ctx context.Context, tenantID, environment string, f settingsField, value map[string]interface{}) error {
	if !ValidEnvironment(environment) {
		return ErrInvalidEnvironment
	}

	scoped, err := r.scopeFor(ctx, tenantID, environment)
	if err != nil {
		return err
	}
	client := r.factory.GetClient(scoped, tenantID, environment)

	exists, err := client.Tenant.Query().Where(tenant.ID(tenantID)).Exist(scoped)
	if err != nil {
		return fmt.Errorf("failed checking tenant existence: %w", err)
	}
	if !exists {
		return ErrTenantNotFound
	}

	row, err := r.row(scoped, tenantID, environment)
	switch {
	case err == nil:
		return r.updateBlob(scoped, client, row.ID, f, value)
	case !ent.IsNotFound(err):
		return fmt.Errorf("failed reading tenant environment settings: %w", err)
	}

	create := client.TenantEnvironment.Create().
		SetID(idgen.New("tenv")).
		SetTenantID(tenantID).
		SetEnvironment(tenantenvironment.Environment(environment))
	applyToCreate(create, f, value)

	if _, err := create.Save(scoped); err != nil {
		if !ent.IsConstraintError(err) {
			return fmt.Errorf("failed creating tenant environment settings: %w", err)
		}
		// The unique index on (tenant_id, environment) rejected this insert, so a
		// concurrent write created the row first. Its policy is as valid as this
		// one; applying this write on top settles the order rather than failing an
		// administrator's save because two arrived together.
		row, err := r.row(scoped, tenantID, environment)
		if err != nil {
			return fmt.Errorf("failed reading tenant environment settings after a concurrent create: %w", err)
		}
		return r.updateBlob(scoped, client, row.ID, f, value)
	}

	return nil
}

// updateBlob applies one column write to an existing settings row.
func (r *Repository) updateBlob(ctx context.Context, client *ent.Client, rowID string, f settingsField, value map[string]interface{}) error {
	update := client.TenantEnvironment.UpdateOneID(rowID)
	applyToUpdate(update, f, value)
	if _, err := update.Save(ctx); err != nil {
		return fmt.Errorf("failed updating tenant environment settings: %w", err)
	}
	return nil
}

// applyToCreate sets one policy column on a new settings row.
func applyToCreate(b *ent.TenantEnvironmentCreate, f settingsField, v map[string]interface{}) {
	switch f {
	case fieldBrandingConfig:
		b.SetBrandingConfig(v)
	case fieldPasswordPolicy:
		b.SetPasswordPolicy(v)
	case fieldSecurityPolicy:
		b.SetSecurityPolicy(v)
	case fieldRecoveryPolicy:
		b.SetRecoveryPolicy(v)
	case fieldSocialProvider:
		b.SetSocialProviders(v)
	case fieldRolePolicy:
		b.SetRolePolicy(v)
	case fieldSessionPolicy:
		b.SetSessionPolicy(v)
	}
}

// applyToUpdate sets one policy column on an existing settings row.
func applyToUpdate(b *ent.TenantEnvironmentUpdateOne, f settingsField, v map[string]interface{}) {
	switch f {
	case fieldBrandingConfig:
		b.SetBrandingConfig(v)
	case fieldPasswordPolicy:
		b.SetPasswordPolicy(v)
	case fieldSecurityPolicy:
		b.SetSecurityPolicy(v)
	case fieldRecoveryPolicy:
		b.SetRecoveryPolicy(v)
	case fieldSocialProvider:
		b.SetSocialProviders(v)
	case fieldRolePolicy:
		b.SetRolePolicy(v)
	case fieldSessionPolicy:
		b.SetSessionPolicy(v)
	}
}

// decode reparses a stored policy column into T, reporting whether it succeeded.
//
// Stored columns are map[string]interface{} rather than the typed struct, so a
// round trip through JSON is how a policy becomes typed. An unparseable column
// yields false and the caller substitutes its default.
func decode[T any](raw map[string]interface{}) (T, bool) {
	var out T
	if len(raw) == 0 {
		return out, false
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return out, false
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, false
	}
	return out, true
}

// encode renders a typed policy as the map shape the JSON column stores.
func encode(v any) map[string]interface{} {
	var out map[string]interface{}
	data, err := json.Marshal(v)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out)
	return out
}

// GetPasswordPolicy returns the tenant's password policy for one environment, or
// DefaultPasswordPolicy when the tenant is missing, has none stored, or has one
// that no longer parses. Stored values are floored and capped on the way out, so a
// policy weakened below the engine's own minimum cannot take effect, and so the
// policy an administrator reads back is the one that will be enforced. The error is
// always nil.
func (r *Repository) GetPasswordPolicy(ctx context.Context, tenantID, environment string) (PasswordPolicy, error) {
	return decodePasswordPolicy(r.blob(ctx, tenantID, environment, fieldPasswordPolicy)), nil
}

// decodePasswordPolicy turns a stored column into an enforceable password policy.
//
// Separate from the read above so that a caller holding a whole Settings — the
// bootstrap document, which needs three policies and would otherwise read the row
// three times — decodes it exactly as a direct read would.
func decodePasswordPolicy(raw map[string]interface{}) PasswordPolicy {
	p, ok := decode[PasswordPolicy](raw)
	if !ok {
		return DefaultPasswordPolicy()
	}

	p.MinLength, p.MaxLength = EffectivePasswordBounds(p)
	if p.EnforcementMode == "" {
		p.EnforcementMode = "require"
	}

	return p
}

// UpdatePasswordPolicy clamps the policy into range, persists it for one
// environment, and returns what was stored. Lengths outside the permitted range and
// an unrecognised enforcement mode are corrected rather than rejected. It returns an
// error only when the write fails.
func (r *Repository) UpdatePasswordPolicy(ctx context.Context, tenantID, environment string, p PasswordPolicy) (PasswordPolicy, error) {
	p.MinLength, p.MaxLength = EffectivePasswordBounds(p)
	if p.EnforcementMode != "require" && p.EnforcementMode != "notify" {
		p.EnforcementMode = "require"
	}

	if err := r.putBlob(ctx, tenantID, environment, fieldPasswordPolicy, encode(p)); err != nil {
		return p, err
	}
	return p, nil
}

// GetSecurityPolicy returns the tenant's security policy for one environment, or
// DefaultSecurityPolicy when the tenant is missing, has none stored, or has one
// that no longer parses. Unrecognised enum values are corrected to their defaults.
// The error is always nil.
func (r *Repository) GetSecurityPolicy(ctx context.Context, tenantID, environment string) (SecurityPolicy, error) {
	return decodeSecurityPolicy(r.blob(ctx, tenantID, environment, fieldSecurityPolicy)), nil
}

// decodeSecurityPolicy turns a stored column into an enforceable security policy,
// for the same reason as decodePasswordPolicy.
func decodeSecurityPolicy(raw map[string]interface{}) SecurityPolicy {
	sp, ok := decode[SecurityPolicy](raw)
	if !ok {
		return DefaultSecurityPolicy()
	}

	sp.EmailVerificationMode = normalizedVerificationMode(sp.EmailVerificationMode)
	sp.TokenReusePolicy = normalizedTokenReusePolicy(sp.TokenReusePolicy)

	return sp
}

// UpdateSecurityPolicy corrects unrecognised enum values, persists the policy for
// one environment, and returns what was stored. It returns an error only when the
// write fails.
func (r *Repository) UpdateSecurityPolicy(ctx context.Context, tenantID, environment string, sp SecurityPolicy) (SecurityPolicy, error) {
	sp.EmailVerificationMode = normalizedVerificationMode(sp.EmailVerificationMode)
	sp.TokenReusePolicy = normalizedTokenReusePolicy(sp.TokenReusePolicy)

	if err := r.putBlob(ctx, tenantID, environment, fieldSecurityPolicy, encode(sp)); err != nil {
		return sp, err
	}
	return sp, nil
}

// normalizedVerificationMode corrects an unrecognised email verification mode to
// the default. Shared by the read and write paths so a value stored by an older
// build is corrected the same way on the way out as a bad value is on the way in.
func normalizedVerificationMode(mode string) string {
	if mode != "hard" && mode != "soft" {
		return "soft"
	}
	return mode
}

// normalizedTokenReusePolicy corrects an unrecognised token reuse policy to the
// default, for the same reason as normalizedVerificationMode.
func normalizedTokenReusePolicy(p string) string {
	if p != "global_revoke" && p != "session_revoke" {
		return "global_revoke"
	}
	return p
}

// GetRecoveryPolicy returns the tenant's recovery policy for one environment, or
// DefaultRecoveryPolicy when the tenant is missing, has none stored, or has one
// that no longer parses. The error is always nil.
func (r *Repository) GetRecoveryPolicy(ctx context.Context, tenantID, environment string) (RecoveryPolicy, error) {
	return decodeRecoveryPolicy(r.blob(ctx, tenantID, environment, fieldRecoveryPolicy)), nil
}

// decodeRecoveryPolicy turns a stored column into a recovery policy, for the same
// reason as decodePasswordPolicy.
func decodeRecoveryPolicy(raw map[string]interface{}) RecoveryPolicy {
	rp, ok := decode[RecoveryPolicy](raw)
	if !ok {
		return DefaultRecoveryPolicy()
	}
	return rp
}

// UpdateRecoveryPolicy validates the policy in full before persisting it for one
// environment and returns what was stored.
//
// Unlike the password and security policies, nothing here is clamped: a recovery
// policy's fields constrain each other — schedule ordering, guardian bounds, method
// toggles — so an out-of-range value is refused rather than silently adjusted into a
// policy the caller did not ask for. It returns the validation error or the write
// error.
func (r *Repository) UpdateRecoveryPolicy(ctx context.Context, tenantID, environment string, rp RecoveryPolicy) (RecoveryPolicy, error) {
	if err := ValidateRecoveryPolicy(rp); err != nil {
		return rp, fmt.Errorf("invalid recovery policy: %w", err)
	}

	if err := r.putBlob(ctx, tenantID, environment, fieldRecoveryPolicy, encode(rp)); err != nil {
		return rp, err
	}
	return rp, nil
}

// GetImpersonationPolicy returns the tenant's impersonation policy for one
// environment, nested under the security policy column, or
// DefaultImpersonationPolicy when the tenant is missing, the key is absent, the
// value does not parse, or the stored policy no longer validates.
//
// Re-validating on read matters: bounds can tighten between releases, and a policy
// stored under looser rules must not keep granting a longer session than the
// current rules permit. The error is always nil.
func (r *Repository) GetImpersonationPolicy(ctx context.Context, tenantID, environment string) (ImpersonationPolicy, error) {
	security := r.blob(ctx, tenantID, environment, fieldSecurityPolicy)
	if security == nil {
		return DefaultImpersonationPolicy(), nil
	}

	raw, ok := security["impersonation_policy"]
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

// UpdateImpersonationPolicy validates the policy and merges it into the
// environment's security policy column, preserving the column's other keys, and
// returns what was stored. It returns the validation error, an error when the
// tenant does not exist, or the write error.
func (r *Repository) UpdateImpersonationPolicy(ctx context.Context, tenantID, environment string, ip ImpersonationPolicy) (ImpersonationPolicy, error) {
	if err := ValidateImpersonationPolicy(ip); err != nil {
		return ip, fmt.Errorf("invalid impersonation policy: %w", err)
	}

	// Read-modify-write on the shared column. The other keys under security_policy
	// belong to a different policy and are carried through untouched, so saving an
	// impersonation policy does not reset email verification along with it.
	security := r.blob(ctx, tenantID, environment, fieldSecurityPolicy)
	if security == nil {
		security = make(map[string]interface{})
	}
	security["impersonation_policy"] = encode(ip)

	if err := r.putBlob(ctx, tenantID, environment, fieldSecurityPolicy, security); err != nil {
		return ip, err
	}
	return ip, nil
}

// GetSessionPolicy returns the tenant's session policy for one environment, or
// DefaultSessionPolicy when the tenant is missing, has none stored, or has one that
// no longer parses. Stored values are normalized on the way out, so a policy written
// under looser bounds cannot keep granting a longer session than the current rules
// permit. The error is always nil.
//
// This sits on the login path and on every cookie write, so it must never fail the
// caller — see the package note on reads degrading to defaults. Callers that want it
// cached should go through settings.Resolver rather than adding a cache here, so
// invalidation has one home.
func (r *Repository) GetSessionPolicy(ctx context.Context, tenantID, environment string) (SessionPolicy, error) {
	return decodeSessionPolicy(r.blob(ctx, tenantID, environment, fieldSessionPolicy)), nil
}

// decodeSessionPolicy turns a stored column into an enforceable session policy, for
// the same reason as decodePasswordPolicy.
func decodeSessionPolicy(raw map[string]interface{}) SessionPolicy {
	sp, ok := decode[SessionPolicy](raw)
	if !ok {
		return DefaultSessionPolicy()
	}
	return NormalizeSessionPolicy(sp)
}

// UpdateSessionPolicy normalizes the policy, persists it for one environment, and
// returns what was stored. It returns ErrTenantNotFound for an unknown tenant, or
// the write error.
//
// Out-of-range values are clamped rather than refused, so a caller asking for a
// ten-year access token receives a 200 describing the day it actually got. The one
// thing not decided here is whether SameSite=None is usable: that depends on the
// deployment's scheme, which this layer does not know, so it is enforced where the
// cookie is built.
func (r *Repository) UpdateSessionPolicy(ctx context.Context, tenantID, environment string, sp SessionPolicy) (SessionPolicy, error) {
	sp = NormalizeSessionPolicy(sp)

	if err := r.putBlob(ctx, tenantID, environment, fieldSessionPolicy, encode(sp)); err != nil {
		return sp, err
	}
	return sp, nil
}

// GetBrandingConfig returns the environment's branding blob, or nil when none is
// stored. Branding has no typed policy or default: it is passed through to the
// login page as configured. The error is always nil.
func (r *Repository) GetBrandingConfig(ctx context.Context, tenantID, environment string) (map[string]interface{}, error) {
	return r.blob(ctx, tenantID, environment, fieldBrandingConfig), nil
}

// UpdateBrandingConfig persists the environment's branding blob.
func (r *Repository) UpdateBrandingConfig(ctx context.Context, tenantID, environment string, cfg map[string]interface{}) error {
	return r.putBlob(ctx, tenantID, environment, fieldBrandingConfig, cfg)
}

// GetSocialProviders returns the environment's per-provider OAuth configuration, or
// nil when none is stored. The error is always nil.
//
// Entries hold encrypted client secrets, so a caller rendering this to a response
// must strip them; see internal/social.
func (r *Repository) GetSocialProviders(ctx context.Context, tenantID, environment string) (map[string]interface{}, error) {
	return r.blob(ctx, tenantID, environment, fieldSocialProvider), nil
}

// UpdateSocialProviders persists the environment's per-provider OAuth configuration.
func (r *Repository) UpdateSocialProviders(ctx context.Context, tenantID, environment string, providers map[string]interface{}) error {
	return r.putBlob(ctx, tenantID, environment, fieldSocialProvider, providers)
}

// GetRolePolicy returns the environment's role and permission policy blob, or nil
// when none is stored. The error is always nil.
func (r *Repository) GetRolePolicy(ctx context.Context, tenantID, environment string) (map[string]interface{}, error) {
	return r.blob(ctx, tenantID, environment, fieldRolePolicy), nil
}

// UpdateRolePolicy persists the environment's role and permission policy blob.
func (r *Repository) UpdateRolePolicy(ctx context.Context, tenantID, environment string, rp map[string]interface{}) error {
	return r.putBlob(ctx, tenantID, environment, fieldRolePolicy, rp)
}

// Snapshot returns every policy column for one environment verbatim.
//
// Used for publishing and for the diff an administrator sees before publishing. A
// tenant with no settings row yields a zero Settings rather than an error, which is
// the honest answer: nothing is stored, so the environment is running on defaults.
func (r *Repository) Snapshot(ctx context.Context, tenantID, environment string) (Settings, error) {
	if !ValidEnvironment(environment) {
		return Settings{}, ErrInvalidEnvironment
	}

	row, err := r.row(ctx, tenantID, environment)
	if err != nil {
		if ent.IsNotFound(err) {
			return Settings{}, nil
		}
		return Settings{}, err
	}

	return settingsOf(row), nil
}

// settingsOf lifts a settings row's policy columns into a Settings.
//
// Separate from Snapshot so that Publish, which already holds the destination row,
// can read its current contents without a second query.
func settingsOf(row *ent.TenantEnvironment) Settings {
	return Settings{
		BrandingConfig:  row.BrandingConfig,
		PasswordPolicy:  row.PasswordPolicy,
		SecurityPolicy:  row.SecurityPolicy,
		RecoveryPolicy:  row.RecoveryPolicy,
		SocialProviders: row.SocialProviders,
		RolePolicy:      row.RolePolicy,
		SessionPolicy:   row.SessionPolicy,
	}
}

// EnsureEnvironment creates the tenant's settings row for one environment if it has
// none, and reports nothing when the row already exists.
//
// Called at provisioning so both environments exist from the start. Not required
// for correctness — every read degrades to defaults and every write creates the row
// it needs — but a tenant whose rows exist can be shown and edited in the console
// without a first write having to conjure them.
func (r *Repository) EnsureEnvironment(ctx context.Context, tenantID, environment string) error {
	if !ValidEnvironment(environment) {
		return ErrInvalidEnvironment
	}

	if _, err := r.row(ctx, tenantID, environment); err == nil {
		return nil
	} else if !ent.IsNotFound(err) {
		return err
	}

	scoped, err := r.scopeFor(ctx, tenantID, environment)
	if err != nil {
		return err
	}

	_, err = r.factory.GetClient(scoped, tenantID, environment).TenantEnvironment.Create().
		SetID(idgen.New("tenv")).
		SetTenantID(tenantID).
		SetEnvironment(tenantenvironment.Environment(environment)).
		Save(scoped)
	if err != nil && !ent.IsConstraintError(err) {
		return fmt.Errorf("failed creating %s environment settings: %w", environment, err)
	}
	return nil
}

// EnsureEnvironments creates both of a tenant's settings rows if absent.
func (r *Repository) EnsureEnvironments(ctx context.Context, tenantID string) error {
	for _, environment := range []string{
		string(tenantenvironment.EnvironmentTest),
		string(tenantenvironment.EnvironmentLive),
	} {
		if err := r.EnsureEnvironment(ctx, tenantID, environment); err != nil {
			return err
		}
	}
	return nil
}

// PublishResult reports what one publish did.
type PublishResult struct {
	// Settings is what the destination now holds — a verbatim copy of the source.
	Settings Settings
	// Changed names the columns the publish altered, measured against the
	// destination as it stood before the write. An empty list means the destination
	// already matched the source, so the publish stamped published_at and changed
	// nothing else.
	Changed []string
}

// Publish copies every policy column from one environment onto the other and
// stamps the destination's published_at.
//
// This is what makes the test environment worth having: a policy is changed in
// test, exercised against test sign-ins, and only then applied to live. The copy is
// verbatim and wholesale — all seven columns, not a selection — because a partially
// published configuration is a state nobody chose and nobody tested. Publishing an
// empty source therefore clears the destination, which is the faithful meaning of
// "make live match test".
//
// The source must not equal the destination: copying an environment onto itself
// would report success while stamping published_at on settings that were never
// published, making the audit trail claim a promotion that did not happen.
func (r *Repository) Publish(ctx context.Context, tenantID, from, to string) (PublishResult, error) {
	if !ValidEnvironment(from) || !ValidEnvironment(to) {
		return PublishResult{}, ErrInvalidEnvironment
	}
	if from == to {
		return PublishResult{}, fmt.Errorf("%w: cannot publish %q onto itself", ErrInvalidEnvironment, from)
	}

	source, err := r.Snapshot(ctx, tenantID, from)
	if err != nil {
		return PublishResult{}, fmt.Errorf("failed reading %s settings to publish: %w", from, err)
	}

	if err := r.EnsureEnvironment(ctx, tenantID, to); err != nil {
		return PublishResult{}, err
	}

	row, err := r.row(ctx, tenantID, to)
	if err != nil {
		return PublishResult{}, fmt.Errorf("failed reading %s settings to publish into: %w", to, err)
	}

	// Measured here, while the destination still holds its old configuration. After
	// the update the two environments are identical by construction, so this is the
	// only point at which "what did publishing change" can be answered.
	changed := DifferingFields(source, settingsOf(row))

	scoped, err := r.scopeFor(ctx, tenantID, to)
	if err != nil {
		return PublishResult{}, err
	}

	// One update rather than seven, so live is never briefly running half of test's
	// configuration and half of its own.
	_, err = r.factory.GetClient(scoped, tenantID, to).TenantEnvironment.UpdateOneID(row.ID).
		SetBrandingConfig(source.BrandingConfig).
		SetPasswordPolicy(source.PasswordPolicy).
		SetSecurityPolicy(source.SecurityPolicy).
		SetRecoveryPolicy(source.RecoveryPolicy).
		SetSocialProviders(source.SocialProviders).
		SetRolePolicy(source.RolePolicy).
		SetSessionPolicy(source.SessionPolicy).
		SetPublishedAt(time.Now()).
		Save(scoped)
	if err != nil {
		return PublishResult{}, fmt.Errorf("failed publishing %s settings to %s: %w", from, to, err)
	}

	return PublishResult{Settings: source, Changed: changed}, nil
}

// PublishAudit is the request context behind one settings promotion.
type PublishAudit struct {
	// From and To name the environments the settings moved between.
	From string
	To   string
	// Changed names the columns the publish altered. Only the names are recorded:
	// the values include encrypted provider secrets, which have no business in a
	// log an administrator can read back.
	Changed []string
	// ActorID identifies who published — a console user, or the secret key used.
	ActorID string
	// APIKeyID names the secret key the request authenticated with, when it did.
	APIKeyID string
	// IPAddress, UserAgent and Origin are the request's network context.
	IPAddress string
	UserAgent string
	Origin    string
}

// RecordPublish appends the audit row for a settings promotion.
//
// Publishing is the one settings operation that changes what governs live
// sign-ins without anybody editing a live policy, so it is the one that most needs
// a trail: "live started requiring 12-character passwords on Tuesday" is otherwise
// unanswerable from the data alone.
//
// The error is returned rather than logged so the caller decides. The caller treats
// it as best-effort, because the promotion is already durable by the time this runs
// and reporting a completed publish as failed would invite a second one.
func (r *Repository) RecordPublish(ctx context.Context, tenantID string, a PublishAudit) error {
	client := r.factory.GetClient(ctx, tenantID, a.To)

	builder := client.AuditLog.Create().
		SetID(idgen.New("log")).
		SetTenantID(tenantID).
		SetActorType(auditlog.ActorTypeAdmin).
		SetEventType("tenant.settings.published").
		SetMetadata(map[string]interface{}{
			"from":            a.From,
			"to":              a.To,
			"changed_columns": a.Changed,
			"actor_id":        a.ActorID,
		})

	if a.APIKeyID != "" {
		builder = builder.SetAPIKeyID(a.APIKeyID)
	}
	if a.IPAddress != "" {
		builder = builder.SetIPAddress(a.IPAddress)
	}
	if a.UserAgent != "" {
		builder = builder.SetUserAgent(a.UserAgent)
	}
	if a.Origin != "" {
		builder = builder.SetRequestOrigin(a.Origin)
	}

	if _, err := builder.Save(ctx); err != nil {
		return fmt.Errorf("failed recording settings publish for tenant %s: %w", tenantID, err)
	}
	return nil
}
