//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/webhook_cascade_test.go
 * Tier: Integration Test
 *
 * Covers deletion of a webhook endpoint that has already dispatched events.
 *
 * Dispatch history is written by the delivery worker and read by nobody at
 * delete time, so the endpoint's own lifecycle depends entirely on the foreign
 * key: whether it cascades decides whether an endpoint that has ever fired can
 * be removed at all.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/webhookendpoint"
)

// TestWebhookEndpointDeletionTakesItsEventsWithIt removes an endpoint that has
// dispatch history.
//
// Nothing in the engine deletes these events first, so a restrictive foreign
// key would make the delete fail — and it would fail only for endpoints that
// have been used, which is every endpoint a customer would want to remove.
func TestWebhookEndpointDeletionTakesItsEventsWithIt(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	ctx := env.bypassContext()
	client := env.client(ctx)

	if _, err := client.WebhookEndpoint.Create().
		SetID("whe_cascade").
		SetTenantID(testTenant).
		SetEnvironment(webhookendpoint.EnvironmentLive).
		SetURL("https://listener.activity.example/hooks").
		SetSecretKeyEncrypted("encrypted-placeholder").
		SetSubscribedEvents([]string{"user.created"}).
		Save(ctx); err != nil {
		t.Fatalf("seeding webhook endpoint: %v", err)
	}
	if _, err := client.WebhookEvent.Create().
		SetID("whev_cascade").
		SetWebhookEndpointID("whe_cascade").
		SetEventType("user.created").
		SetPayload(map[string]interface{}{"id": "usr_example"}).
		SetStatus("success").
		Save(ctx); err != nil {
		t.Fatalf("seeding webhook event: %v", err)
	}

	if err := client.WebhookEndpoint.DeleteOneID("whe_cascade").Exec(ctx); err != nil {
		t.Fatalf("deleting an endpoint that has dispatched events: %v", err)
	}

	remaining, err := client.WebhookEvent.Query().Count(ctx)
	if err != nil {
		t.Fatalf("counting webhook events: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("webhook events surviving their endpoint: got %d, want 0", remaining)
	}
}
