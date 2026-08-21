/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/authcookie/authcookie_test.go
 * Tier: Delivery Layer / Unit Tests
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package authcookie_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/authcookie"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

// stubPolicies returns one fixed policy for every tenant, standing in for the
// settings cache.
type stubPolicies struct {
	sp policy.SessionPolicy
}

func (s stubPolicies) SessionPolicy(context.Context, string, string) policy.SessionPolicy {
	return s.sp
}

// deploymentConfig is a Config carrying only the lifetimes these tests resolve
// against: a month of refresh, and a test environment capped at a day.
func deploymentConfig() *config.Config {
	return &config.Config{
		RefreshTokenTTL: 720 * time.Hour,
		AccessTokenTTL:  15 * time.Minute,
		TestSessionTTL:  24 * time.Hour,
	}
}

func TestWriter_RefreshTokenTTL_PrefersTenantOverDeployment(t *testing.T) {
	w := authcookie.NewWriter(deploymentConfig(), stubPolicies{
		sp: policy.SessionPolicy{RefreshTokenTTLDays: 2},
	})

	assert.Equal(t, 48*time.Hour, w.RefreshTokenTTL(context.Background(), "tnt_x", "live"))
}

func TestWriter_RefreshTokenTTL_FallsBackToDeploymentWhenUnset(t *testing.T) {
	w := authcookie.NewWriter(deploymentConfig(), stubPolicies{sp: policy.SessionPolicy{}})

	assert.Equal(t, 720*time.Hour, w.RefreshTokenTTL(context.Background(), "tnt_x", "live"))
}

func TestWriter_RefreshTokenTTL_TestCeilingLowersTenantChoice(t *testing.T) {
	w := authcookie.NewWriter(deploymentConfig(), stubPolicies{
		sp: policy.SessionPolicy{RefreshTokenTTLDays: 30},
	})

	// The tenant's one setting governs both environments, so test is bounded while
	// live keeps what was asked for.
	assert.Equal(t, 24*time.Hour, w.RefreshTokenTTL(context.Background(), "tnt_x", "test"))
	assert.Equal(t, 720*time.Hour, w.RefreshTokenTTL(context.Background(), "tnt_x", "live"))
}

func TestWriter_RefreshTokenTTL_CeilingDoesNotRaiseAShorterChoice(t *testing.T) {
	w := authcookie.NewWriter(deploymentConfig(), stubPolicies{
		sp: policy.SessionPolicy{RefreshTokenTTLDays: 1},
	})

	// A tenant asking for less than the ceiling keeps it. The ceiling lowers and
	// never raises, or shortening a window would be undone in test.
	assert.Equal(t, 24*time.Hour, w.RefreshTokenTTL(context.Background(), "tnt_x", "test"))
}

func TestWriter_RefreshTokenTTLOr_UsesCallerFallbackOnlyWhenTenantIsUnset(t *testing.T) {
	const passkeyWeek = 7 * 24 * time.Hour

	unset := authcookie.NewWriter(deploymentConfig(), stubPolicies{sp: policy.SessionPolicy{}})
	assert.Equal(t, passkeyWeek,
		unset.RefreshTokenTTLOr(context.Background(), "tnt_x", "live", passkeyWeek))

	// A tenant that configured a window outranks the path's own default, including
	// when that lengthens the session past the week a passkey login would grant.
	configured := authcookie.NewWriter(deploymentConfig(), stubPolicies{
		sp: policy.SessionPolicy{RefreshTokenTTLDays: 30},
	})
	assert.Equal(t, 720*time.Hour,
		configured.RefreshTokenTTLOr(context.Background(), "tnt_x", "live", passkeyWeek))
}

func TestWriter_NilResolverYieldsDeploymentLifetimes(t *testing.T) {
	w := authcookie.NewWriter(deploymentConfig(), nil)

	assert.Equal(t, 720*time.Hour, w.RefreshTokenTTL(context.Background(), "tnt_x", "live"))
	assert.Equal(t, 15*time.Minute, w.AccessTokenTTL(context.Background(), "tnt_x", "live"))
}
