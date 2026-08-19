/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/quota/quota.go
 * Tier: Internal Feature Package / Test-Environment Ceilings
 *
 * Bounds how much data a test environment may hold, and how long a session opened
 * there may live, at the ORM, so neither ceiling depends on every create path
 * remembering to ask for it.
 *
 * A test environment is free and unmetered, which makes it the cheapest place to
 * run something that is not a test. The ceilings here are what keep it a
 * development surface: a few hundred users is more than any test suite needs and
 * far less than a product, so the limit is invisible to the intended use and
 * decisive against the other one.
 *
 * The check sits in a mutation hook rather than in the services because there are
 * five paths that create a user — sign-up, magic-link auto-provisioning, social
 * sign-in, SAML provisioning and invitation acceptance — and a ceiling enforced by
 * convention holds only until the sixth is written. Underneath the query builder
 * there is nothing to remember: a create either has room or does not. The session
 * lifetime is bounded from the same place for the same reason, each sign-in path
 * having its own idea of how long a session should last.
 *
 * Two rules differ deliberately from the privacy interceptor next door, which
 * this file otherwise mirrors:
 *
 *   - An entity type absent from the switch is allowed rather than refused. The
 *     privacy interceptor must refuse, because an unscoped query spans tenants.
 *     This one bounds a handful of row kinds, and a default that refused would
 *     stop every other write the engine makes.
 *
 *   - A context with no scope, a bypass context, or a live one passes untouched.
 *     Bypass belongs to migration, seeding and the retention sweeps, none of
 *     which is a tenant spending its allowance.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package quota

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// ErrExceeded reports a create refused for want of room under a test-environment
// ceiling.
//
// Unlike a privacy violation it is a client fault, not an internal one: the
// request was well formed and the caller is who they say they are, there is
// simply no room left. Handlers answer it with 403 rather than 500.
var ErrExceeded = errors.New("test environment quota exceeded")

// Exceeded is the refusal itself, naming what ran out and at what ceiling.
//
// It is a type rather than a formatted error so that a handler can recover the
// caller-facing message with errors.As after the repositories have wrapped it
// ("failed creating user: ..."). Those prefixes name internal operations and must
// not reach a response, and reconstructing the message is more reliable than
// cutting the wrapping back off a string.
type Exceeded struct {
	// Resource is the plural noun for what ran out, as a caller would say it.
	Resource string
	// Limit is the ceiling that was reached.
	Limit int
}

// Error renders the refusal for both the log and the response.
//
// It is written for the operator who meets it during development, so it says what
// to do next: the ceiling belongs to the test environment, and the live one is
// where volume goes.
func (e *Exceeded) Error() string {
	return fmt.Sprintf("the test environment holds its limit of %d %s for this tenant; remove some, or use a live key",
		e.Limit, e.Resource)
}

// Is reports Exceeded as ErrExceeded, so callers that only need to know the kind
// of failure can match the sentinel without naming the type.
func (e *Exceeded) Is(target error) bool {
	return target == ErrExceeded
}

// Limits is the ceiling on how many rows of each capped kind a tenant may hold in
// the test environment, and on how long a session it opens there may live.
//
// A non-positive value leaves that kind uncapped. That is the safe reading of an
// unset field: a zero-valued Limits — one nobody configured — bounds nothing,
// where a zero read as "none allowed" would refuse the first sign-up of a
// deployment whose operator never asked for a ceiling at all. The loader supplies
// positive values for all of them, so a configured deployment is always bounded.
type Limits struct {
	// Users is the ceiling on test users for one tenant.
	Users int
	// Organizations is the ceiling on the tenant's test workspaces. Organizations
	// carry an environment of their own, so a tenant's live workspaces do not
	// consume the room its test ones have.
	Organizations int
	// APIKeys is the ceiling on test API keys for one tenant, counting the pair
	// provisioning installs with a new application.
	APIKeys int
	// SessionTTL is the longest a test session may remain refreshable. Unlike the
	// counts, this one is enforced by rewriting the row rather than by refusing it:
	// a sign-in asking for too long a session is a lifetime to shorten, not a
	// request to turn away.
	SessionTTL time.Duration
}

// Bounded reports whether any ceiling is set, so a caller can tell a configured
// Limits from an empty one.
func (l Limits) Bounded() bool {
	return l.Users > 0 || l.Organizations > 0 || l.APIKeys > 0 || l.SessionTTL > 0
}

// AttachHook installs the test-environment ceilings on an Ent client.
//
// Call it once per client, after AttachPrivacyInterceptors: the counting query
// this hook issues is scoped by those interceptors, which is what makes the count
// per tenant and per environment without any predicate written here. A Limits
// that bounds nothing installs no hook, so an unconfigured client pays nothing.
func AttachHook(client *ent.Client, limits Limits) {
	if !limits.Bounded() {
		return
	}
	client.Use(limits.enforce)
}

// enforce refuses a create that would put a tenant over one of its ceilings, and
// shortens one that asked for more session lifetime than the environment allows.
func (l Limits) enforce(next ent.Mutator) ent.Mutator {
	return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
		if !m.Op().Is(ent.OpCreate) {
			return next.Mutate(ctx, m)
		}

		p, ok := privacy.FromContext(ctx)
		if !ok || p.Bypass || p.Environment != string(user.EnvironmentTest) {
			return next.Mutate(ctx, m)
		}

		l.clampSessionExpiry(m)
		if err := l.check(ctx, m); err != nil {
			return nil, err
		}
		return next.Mutate(ctx, m)
	})
}

// clampSessionExpiry pulls a test session's expiry back to the ceiling.
//
// The services resolve the lifetime themselves, and every sign-in path there is
// already bounded; this is the floor under them. A session row is what makes a
// refresh token work, so a path that computed its own expiry — a passkey login's
// week, an SSO assertion, whatever is written next — would otherwise leave a
// test credential live for as long as it liked with nothing to notice.
//
// A create that names no expiry is left alone. The column is required, so Ent
// refuses that mutation on its own, and inventing a value here would turn a
// programming fault into a silently short-lived session instead.
func (l Limits) clampSessionExpiry(m ent.Mutation) {
	if l.SessionTTL <= 0 {
		return
	}
	mut, ok := m.(*ent.SessionMutation)
	if !ok {
		return
	}
	expiresAt, ok := mut.ExpiresAt()
	if !ok {
		return
	}

	ceiling := time.Now().UTC().Add(l.SessionTTL)
	if expiresAt.After(ceiling) {
		mut.SetExpiresAt(ceiling)
	}
}

// check counts what the tenant already holds of the kind being created.
//
// Each case hands room the query's own Count method rather than a number, so the
// count is issued only for a kind that is actually capped.
func (l Limits) check(ctx context.Context, m ent.Mutation) error {
	switch mut := m.(type) {

	case *ent.UserMutation:
		return room(ctx, "users", l.Users, mut.Client().User.Query().Count)

	case *ent.OrganizationMutation:
		return room(ctx, "organizations", l.Organizations, mut.Client().Organization.Query().Count)

	case *ent.ApiKeyMutation:
		return room(ctx, "API keys", l.APIKeys, mut.Client().ApiKey.Query().Count)

	// Every other entity is unconstrained. Sessions, audit entries and the rest
	// follow from the rows above rather than being provisioned on their own, so
	// bounding the three that are created deliberately bounds the tenant.
	default:
		return nil
	}
}

// room reports whether one more row fits under limit, refusing when it does not.
//
// The count is read immediately before the insert but outside any lock, so two
// creates arriving together can both find room and leave the tenant one row over.
// That is accepted: this is a spend control, not a security boundary, and a
// ceiling enforced to the exact row would cost a serialized count on every
// sign-up in the test environment to prevent an overshoot nobody can observe.
func room(ctx context.Context, resource string, limit int, count func(context.Context) (int, error)) error {
	if limit <= 0 {
		return nil
	}

	existing, err := count(ctx)
	if err != nil {
		return fmt.Errorf("counting %s against the test-environment ceiling: %w", resource, err)
	}
	if existing >= limit {
		return &Exceeded{Resource: resource, Limit: limit}
	}
	return nil
}
