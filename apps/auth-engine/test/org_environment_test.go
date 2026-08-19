//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/org_environment_test.go
 * Tier: Integration Tests / Organization Environment Split
 *
 * Drives the environment boundary on organizations over HTTP, where the two
 * properties that matter are visible together: which credential can read a
 * workspace, and which slugs are still available to it.
 *
 * Both are enforced beneath the handlers — one by the privacy interceptor's
 * predicate, the other by a unique index — so neither is observable from a unit
 * test of the service. What a caller actually gets back is the contract.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"testing"
)

// orgReply is the subset of an organization response these tests assert on.
type orgReply struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Environment string `json:"environment"`
}

// orgListReply is a tenant-tier organization listing.
type orgListReply struct {
	Organizations []orgReply `json:"organizations"`
	Total         int        `json:"total"`
}

// listOrganizations reads the tenant-tier listing with the credential the
// decorator presents, which is what selects the environment the page describes.
func (e *testEnv) listOrganizations(t *testing.T, decorate ...func(*http.Request)) orgListReply {
	t.Helper()

	resp := e.do(t, http.MethodGet, "/v1/tenant/organizations", nil,
		append([]func(*http.Request){withHeader("X-Authn-Secret-Key", secretKey)}, decorate...)...)
	assertStatus(t, "listing organizations", resp, http.StatusOK)

	var page orgListReply
	resp.json(t, &page)
	return page
}

// slugsOf returns the slugs in a page, in the order the page listed them.
func slugsOf(page orgListReply) []string {
	out := make([]string, 0, len(page.Organizations))
	for _, o := range page.Organizations {
		out = append(out, o.Slug)
	}
	return out
}

// TestOrganizationTakesItsEnvironmentFromTheCredential pins where the environment
// comes from: the key, never the request body.
//
// A workspace filed under an environment its creator cannot read would be
// unreachable from the moment it was created, so the response echoing the
// environment is what lets a caller confirm the two agree.
func TestOrganizationTakesItsEnvironmentFromTheCredential(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.createOrganization(t, "from-test-key")
	assertStatus(t, "organization created with a test key", resp, http.StatusCreated)

	var created orgReply
	resp.json(t, &created)
	if created.Environment != "test" {
		t.Errorf("organization created with a test key reports environment %q, want \"test\"", created.Environment)
	}

	resp = env.createOrganization(t, "from-live-key", withLiveSecretKey())
	assertStatus(t, "organization created with a live key", resp, http.StatusCreated)

	resp.json(t, &created)
	if created.Environment != "live" {
		t.Errorf("organization created with a live key reports environment %q, want \"live\"", created.Environment)
	}
}

// TestATestWorkspaceIsInvisibleToALiveCredential is the isolation the split exists
// for. A rehearsal must not appear in a production listing, and a production
// workspace must not be reachable with a key a developer pastes into a scratch
// script.
func TestATestWorkspaceIsInvisibleToALiveCredential(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.createOrganization(t, "rehearsal")
	assertStatus(t, "test workspace", resp, http.StatusCreated)
	var rehearsal orgReply
	resp.json(t, &rehearsal)

	resp = env.createOrganization(t, "production", withLiveSecretKey())
	assertStatus(t, "live workspace", resp, http.StatusCreated)
	var production orgReply
	resp.json(t, &production)

	t.Run("each listing shows only its own environment", func(t *testing.T) {
		if got := slugsOf(env.listOrganizations(t)); len(got) != 1 || got[0] != "rehearsal" {
			t.Errorf("the test listing holds %v, want [rehearsal]", got)
		}
		if got := slugsOf(env.listOrganizations(t, withLiveSecretKey())); len(got) != 1 || got[0] != "production" {
			t.Errorf("the live listing holds %v, want [production]", got)
		}
	})

	// 404 rather than 403 on a cross-environment read, because the two environments
	// are meant to be separate installations as far as a credential can tell:
	// distinguishing "not yours" from "does not exist" would confirm the ID.
	t.Run("a direct read across the boundary is not found", func(t *testing.T) {
		resp := env.do(t, http.MethodGet, "/v1/tenant/organizations/"+rehearsal.ID, nil,
			withLiveSecretKey())
		assertStatus(t, "live credential reading a test workspace", resp, http.StatusNotFound)

		resp = env.do(t, http.MethodGet, "/v1/tenant/organizations/"+production.ID, nil,
			withHeader("X-Authn-Secret-Key", secretKey))
		assertStatus(t, "test credential reading a live workspace", resp, http.StatusNotFound)
	})

	// A delete is a mutation, and the interceptors narrow mutations by the same
	// predicate they narrow reads by. Were only reads confined, a test key could
	// destroy a production workspace it could not even list.
	t.Run("a delete across the boundary is refused", func(t *testing.T) {
		resp := env.do(t, http.MethodDelete, "/v1/tenant/organizations/"+production.ID, nil,
			withHeader("X-Authn-Secret-Key", secretKey))
		assertStatus(t, "test credential deleting a live workspace", resp, http.StatusNotFound)

		if got := len(env.listOrganizations(t, withLiveSecretKey()).Organizations); got != 1 {
			t.Errorf("the live listing holds %d workspaces after a refused delete, want 1", got)
		}
	})
}

// TestTheSameSlugIsAvailableInBothEnvironments is the practical payoff of the
// split. A team rehearses under the slug it means to ship, and a slug that could be
// claimed only once would force every test workspace to carry a name that is not the
// one being tested.
func TestTheSameSlugIsAvailableInBothEnvironments(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.createOrganization(t, "acme")
	assertStatus(t, "test workspace named acme", resp, http.StatusCreated)

	resp = env.createOrganization(t, "acme", withLiveSecretKey())
	assertStatus(t, "live workspace named acme", resp, http.StatusCreated)

	// Within one environment it is still taken, or the uniqueness that keeps a slug
	// addressable has been traded away rather than narrowed.
	t.Run("a repeat within one environment is refused", func(t *testing.T) {
		resp := env.createOrganization(t, "acme")
		if resp.status != http.StatusBadRequest && resp.status != http.StatusConflict {
			t.Errorf("second test workspace named acme: got status %d, want 400 or 409; body %s",
				resp.status, resp.body)
		}
		if got := len(env.listOrganizations(t).Organizations); got != 1 {
			t.Errorf("the test listing holds %d workspaces after a refused create, want 1", got)
		}
	})
}
