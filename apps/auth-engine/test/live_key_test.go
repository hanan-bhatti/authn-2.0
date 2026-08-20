//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/live_key_test.go
 * Tier: Integration Tests / Live-Only Configuration
 *
 * Drives the two surfaces a test credential must not reach: the webhook endpoint
 * list, which has no test counterpart and governs where live events land, and a
 * SAML connection in live, which is the record an organization's real employees
 * authenticate through.
 *
 * Both refusals are only observable here. The webhook one is a middleware, so no
 * service test reaches it, and the SAML one turns on the credential the request
 * arrived with rather than on any argument a service receives.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"testing"
)

// samlCertPEM is the certificate the SAML cases present.
//
// It needs only to satisfy the PEM check the request validator runs, because the
// point of these cases is which credential is allowed to store a certificate at
// all — not whether an assertion signed by this one would verify.
const samlCertPEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAL0b2+
-----END CERTIFICATE-----`

// webhookEndpointReply is the subset of a webhook endpoint response these tests
// assert on.
type webhookEndpointReply struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Environment string `json:"environment"`
}

// createWebhookEndpoint files an endpoint with the live key and returns it, which
// is the only credential that can, and is what the refusal cases need to address.
func (e *testEnv) createWebhookEndpoint(t *testing.T, url string) webhookEndpointReply {
	t.Helper()

	resp := e.do(t, http.MethodPost, "/v1/admin/webhooks/endpoints", map[string]any{
		"url":         url,
		"description": "Live receiver",
		"environment": "live",
		"events":      []string{"user.created"},
	}, withLiveSecretKey())
	assertStatus(t, "creating a webhook endpoint with the live key", resp, http.StatusCreated)

	var created webhookEndpointReply
	resp.json(t, &created)
	return created
}

// TestWebhookConfigurationRefusesATestKey covers every route that changes the
// endpoint list or makes it emit a request.
//
// An endpoint's environment is chosen by whoever registers it, so a write may
// name live — or "all" — whichever key made it. A test key could otherwise point
// live traffic at a destination of its choosing, repoint an entry to redirect a
// live event, or delete one to silence a live integration.
func TestWebhookConfigurationRefusesATestKey(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	endpoint := env.createWebhookEndpoint(t, "https://hooks.example.com/live")

	cases := []struct {
		name    string
		method  string
		path    string
		payload any
	}{
		{"create", http.MethodPost, "/v1/admin/webhooks/endpoints", map[string]any{
			"url":         "https://hooks.example.com/injected",
			"environment": "live",
			"events":      []string{"user.created"},
		}},
		{"update", http.MethodPut, "/v1/admin/webhooks/endpoints/" + endpoint.ID, map[string]any{
			"url": "https://attacker.example.com/collect",
		}},
		{"delete", http.MethodDelete, "/v1/admin/webhooks/endpoints/" + endpoint.ID, nil},
		{"ping", http.MethodPost, "/v1/admin/webhooks/endpoints/" + endpoint.ID + "/ping", nil},
		{"rotate secret", http.MethodPost, "/v1/admin/webhooks/endpoints/" + endpoint.ID + "/rotate-secret", nil},
		{"redeliver", http.MethodPost, "/v1/admin/webhooks/deliveries/evt_absent/redeliver", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.do(t, tc.method, tc.path, tc.payload, withSecretKey())
			assertRefusedWith(t, tc.name+" with a test key", resp, http.StatusForbidden, "live_key_required")
		})
	}

	// The endpoint is re-read with the credential that owns it, because a refusal
	// that had already written is not a refusal.
	t.Run("nothing was changed", func(t *testing.T) {
		resp := env.do(t, http.MethodGet, "/v1/admin/webhooks/endpoints/"+endpoint.ID, nil, withLiveSecretKey())
		assertStatus(t, "re-reading the endpoint", resp, http.StatusOK)

		var reread webhookEndpointReply
		resp.json(t, &reread)
		if reread.URL != endpoint.URL {
			t.Errorf("the refused update landed anyway: URL is now %q", reread.URL)
		}
	})
}

// TestWebhookConfigurationIsReadableWithATestKey is the deliberate asymmetry, and
// the same one the settings publish endpoint draws: seeing the other environment's
// configuration crosses nothing, changing it does. A console signed in against test
// can still show a tenant what it has configured.
func TestWebhookConfigurationIsReadableWithATestKey(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	endpoint := env.createWebhookEndpoint(t, "https://hooks.example.com/readable")

	for _, path := range []string{
		"/v1/admin/webhooks/endpoints",
		"/v1/admin/webhooks/endpoints/" + endpoint.ID,
		"/v1/admin/webhooks/deliveries",
	} {
		resp := env.do(t, http.MethodGet, path, nil, withSecretKey())
		assertStatus(t, "reading "+path+" with a test key", resp, http.StatusOK)
	}
}

// TestSAMLConnectionInLiveRefusesATestKey pins the environment on a connection to
// the credential that supplied it.
//
// The field arrives in the request body, so without the guard the weaker
// credential picks its own environment — and because the schema default for this
// entity is live, it does so by sending nothing at all.
func TestSAMLConnectionInLiveRefusesATestKey(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	// The organization is created with the same test key, so it is a workspace the
	// caller genuinely owns. What it may not do is attach a live connection to it.
	resp := env.do(t, http.MethodPost, "/v1/tenant/organizations", map[string]any{
		"name": "Siemens AG",
		"slug": "siemens",
	}, withSecretKey())
	assertStatus(t, "creating a test organization", resp, http.StatusCreated)

	var org orgReply
	resp.json(t, &org)

	connection := func(domain, environment string) map[string]any {
		body := map[string]any{
			"idp_entity_id":   "http://www.okta.com/exk1fv49h8VqQhQGD5d7",
			"idp_sso_url":     "https://siemens.okta.com/app/sso/saml",
			"idp_certificate": samlCertPEM,
			"allowed_domains": []string{domain},
		}
		if environment != "" {
			body["environment"] = environment
		}
		return body
	}
	path := "/v1/tenant/organizations/" + org.ID + "/saml"

	refused := env.do(t, http.MethodPost, path, connection("siemens.com", "live"), withSecretKey())
	assertRefusedWith(t, "a test key naming live", refused, http.StatusForbidden, "live_key_required")

	t.Run("an omitted environment is the same request", func(t *testing.T) {
		resp := env.do(t, http.MethodPost, path, connection("siemens.de", ""), withSecretKey())
		assertRefusedWith(t, "a test key omitting environment", resp, http.StatusForbidden, "live_key_required")
	})

	t.Run("a test connection is admitted", func(t *testing.T) {
		resp := env.do(t, http.MethodPost, path, connection("siemens.at", "test"), withSecretKey())
		assertStatus(t, "a test key configuring a test connection", resp, http.StatusCreated)
	})

	// Promotion is the other route into live, and it belongs to the live key too:
	// owning the trial is not owning the decision to put an identity provider in
	// front of real employees.
	t.Run("nor may it promote the connection it owns", func(t *testing.T) {
		resp := env.do(t, http.MethodPatch, path, map[string]any{"environment": "live"}, withSecretKey())
		assertRefusedWith(t, "a test key promoting its own connection", resp, http.StatusForbidden, "live_key_required")
	})
}
