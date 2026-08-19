//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/sandbox_test.go
 * Tier: Integration Tests / Sandbox Inbox & Delivery Verification
 *
 * Covers the two halves of test-environment message handling, which answer
 * different questions and are asserted separately here for that reason.
 *
 * The inbox is what a test environment does with a message: a signup runs to
 * completion, nothing reaches a provider, and the rendered message is readable
 * with the credential it carries intact. The assertions that matter most are the
 * negative ones — that the provider behind the sandbox saw nothing, that a live
 * credential is refused rather than shown an empty list, and that one tenant's
 * purge leaves another's captures alone.
 *
 * Delivery verification is the deliberate exception: the one endpoint whose
 * purpose is to reach a real provider, so the test asserts that its message
 * bypassed the capture and that the recipient came from the signed-in operator's
 * account rather than from the request.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sandboxmessage"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sandbox"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// The routes under test.
const (
	sandboxInboxPath   = "/v1/tenant/sandbox/messages"
	deliveryVerifyPath = "/v1/tenant/delivery/verify"
)

// inboxListing is the inbox index response.
//
// The message shape is the handler's own DTO rather than a copy of it, so a
// renamed or removed field fails to compile here instead of quietly decoding as a
// zero value and passing.
type inboxListing struct {
	Environment string               `json:"environment"`
	Messages    []sandbox.MessageDTO `json:"messages"`
	Total       int                  `json:"total"`
}

// inboxRead is the single-message response.
type inboxRead struct {
	Environment string             `json:"environment"`
	Message     sandbox.MessageDTO `json:"message"`
}

// purgeReply is the response to emptying an inbox.
type purgeReply struct {
	Environment string `json:"environment"`
	Removed     int    `json:"removed"`
}

// deliveryReply is the response to a delivery verification that the provider
// accepted.
type deliveryReply struct {
	Channel   string `json:"channel"`
	Recipient string `json:"recipient"`
	Driver    string `json:"driver"`
}

// withLiveSecretKey presents the live-environment credential belonging to the same
// seeded application.
//
// It is valid, so the guard admits it; what it is not is a credential addressing
// the environment the sandbox exists in.
func withLiveSecretKey() func(*http.Request) {
	return withHeader("X-Authn-Secret-Key", liveSecretKey)
}

// withConsoleSession presents the access token a signed-in console operator would
// carry, with the administrator role the admin guard requires.
//
// The token is signed here rather than obtained by driving a login, because
// role=tenant_admin comes from an operator's membership rather than from anything
// the client signup routes issue. The harness supplies no second-factor validator,
// so no enrolment is needed for the guard to admit it.
func (e *testEnv) withConsoleSession(t *testing.T, userID, address string) func(*http.Request) {
	t.Helper()

	token, err := jwtpkg.IssueAccessToken(userID, testTenant, testEnvironment,
		address, "Delivery Operator", "tenant_admin", e.cfg.EncryptionKey, 15*time.Minute)
	if err != nil {
		t.Fatalf("issuing a console session token for %s: %v", userID, err)
	}
	return withHeader("Authorization", "Bearer "+token)
}

// captureFor writes one message into a tenant's inbox through the store, under
// that tenant's own scope.
//
// It exists to give a test a second tenant's capture to be refused. Nothing a
// request can drive would produce one, since a capture is scoped to the tenant
// whose credential made the send.
func (e *testEnv) captureFor(t *testing.T, tenantID, recipient string) string {
	t.Helper()

	ctx := privacy.NewContext(context.Background(), tenantID, "", testEnvironment)
	m, err := e.sandboxStore.Capture(ctx, sandbox.Message{
		Channel:   sandboxmessage.ChannelEmail,
		Recipient: recipient,
		Subject:   "Planted capture",
		Body:      "<p>planted</p>",
	})
	if err != nil {
		t.Fatalf("capturing a message for %s: %v", tenantID, err)
	}
	return m.ID
}

// inboxCount returns how many messages a tenant's test-environment inbox holds,
// read through the store rather than over HTTP so it can be asked about a tenant
// the suite holds no credential for.
func (e *testEnv) inboxCount(t *testing.T, tenantID string) int {
	t.Helper()

	ctx := privacy.NewContext(context.Background(), tenantID, "", testEnvironment)
	_, total, err := e.sandboxStore.List(ctx, sandbox.Filter{})
	if err != nil {
		t.Fatalf("counting the inbox for %s: %v", tenantID, err)
	}
	return total
}

// markEmailVerified flips a user's verified flag directly.
//
// The verification round trip has a test of its own; here the flag is only the
// precondition delivery verification checks before it will use an operator's own
// address, so the account is put into the state an already-verified one presents.
func (e *testEnv) markEmailVerified(t *testing.T, userID string) {
	t.Helper()

	ctx := e.bypassContext()
	if err := e.client(ctx).User.UpdateOneID(userID).SetEmailVerified(true).Exec(ctx); err != nil {
		t.Fatalf("marking %s email-verified: %v", userID, err)
	}
}

// setVerifiedPhone gives a user a verified phone number.
//
// The phone verification flow needs an SMS round trip that no integration test
// drives, so the column is written the way a completed enrolment would leave it.
func (e *testEnv) setVerifiedPhone(t *testing.T, userID, number string) {
	t.Helper()

	ctx := e.bypassContext()
	if err := e.client(ctx).User.UpdateOneID(userID).
		SetPhoneNumber(number).
		SetPhoneVerified(true).
		Exec(ctx); err != nil {
		t.Fatalf("setting a verified phone number on %s: %v", userID, err)
	}
}

// TestSandboxCapturesSignupVerificationEmail walks the path the sandbox exists
// for: a signup in the test environment, no message delivered, and the rendered
// message readable from the inbox with its link intact.
func TestSandboxCapturesSignupVerificationEmail(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "sandbox_capture@example.com"
	signupResp := env.signUp(t, address, "SecurePass123!", "Sandbox Capture")
	if signupResp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", signupResp.status, signupResp.body)
	}

	// A signup made through the publishable key acts in the test environment, and
	// the whole purpose of that is that its message stops at the sandbox. A message
	// found here is one that left for a real inbox.
	if delivered := env.emails.messagesTo(address); len(delivered) != 0 {
		t.Fatalf("%d message(s) reached the provider for %s; a test-environment send must be captured, not delivered",
			len(delivered), address)
	}

	resp := env.do(t, http.MethodGet, sandboxInboxPath, nil, withSecretKey())
	if resp.status != http.StatusOK {
		t.Fatalf("listing the inbox: got status %d, want 200; body %s", resp.status, resp.body)
	}

	var listing inboxListing
	resp.json(t, &listing)
	if listing.Environment != testEnvironment {
		t.Errorf("inbox reports environment %q, want %q", listing.Environment, testEnvironment)
	}
	if listing.Total != 1 {
		t.Fatalf("inbox holds %d message(s), want 1; body %s", listing.Total, resp.body)
	}
	if len(listing.Messages) != 1 {
		t.Fatalf("inbox page carries %d message(s), want 1; body %s", len(listing.Messages), resp.body)
	}

	msg := listing.Messages[0]
	if msg.Channel != "email" {
		t.Errorf("captured channel is %q, want \"email\"", msg.Channel)
	}
	if msg.Environment != testEnvironment {
		t.Errorf("captured message reports environment %q, want %q", msg.Environment, testEnvironment)
	}
	if msg.Recipient != address {
		t.Errorf("captured recipient is %q, want %q", msg.Recipient, address)
	}
	if msg.Template != "email_verification" {
		t.Errorf("captured template is %q, want \"email_verification\"", msg.Template)
	}
	if msg.Subject == "" {
		t.Error("captured message carries no subject line")
	}
	// The listing omits the rendered document, so paging an inbox does not mean
	// transferring every message body that matched.
	if msg.Body != "" {
		t.Errorf("listing carried a message body of %d bytes; the body belongs to the single-message read", len(msg.Body))
	}

	// The link is lifted into its own field precisely so a harness reaching for the
	// credential does not have to parse rendered HTML.
	link, ok := msg.Metadata["link"].(string)
	if !ok || link == "" {
		t.Fatalf("captured message carries no action link in metadata: %#v", msg.Metadata)
	}
	if _, ok := tokenFromBody(link); !ok {
		t.Errorf("the captured action link %q carries no token", link)
	}

	detail := env.do(t, http.MethodGet, sandboxInboxPath+"/"+msg.ID, nil, withSecretKey())
	if detail.status != http.StatusOK {
		t.Fatalf("reading captured message %s: got status %d, want 200; body %s",
			msg.ID, detail.status, detail.body)
	}

	var read inboxRead
	detail.json(t, &read)
	if read.Message.ID != msg.ID {
		t.Errorf("read back message %q, want %q", read.Message.ID, msg.ID)
	}
	if read.Message.Body == "" {
		t.Fatal("the single-message read carries no body, which is the field it exists to add")
	}
	if !strings.Contains(read.Message.Body, "token=") {
		t.Error("the stored body carries no verification token, so a harness could not complete the flow from it")
	}
}

// TestSandboxInboxRefusesALiveCredential drives every inbox route with a valid
// secret key for the live environment.
//
// The refusal is the assertion, not an empty listing: nothing is ever captured
// outside test, so an empty list would be a true answer that reads as "the message
// was never sent" — the one conclusion a sandbox must not produce falsely.
func TestSandboxInboxRefusesALiveCredential(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"list", http.MethodGet, sandboxInboxPath},
		{"read", http.MethodGet, sandboxInboxPath + "/sbxmsg_00000000000000000000000000"},
		{"purge", http.MethodDelete, sandboxInboxPath},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.do(t, tc.method, tc.path, nil, withLiveSecretKey())
			if resp.status != http.StatusForbidden {
				t.Fatalf("%s %s with a live key: got status %d, want 403; body %s",
					tc.method, tc.path, resp.status, resp.body)
			}

			var reply errorReply
			resp.json(t, &reply)
			// A 403 rather than a 401 is what says the credential was accepted and the
			// environment was the problem.
			if reply.Code != "forbidden" {
				t.Errorf("refusal code is %q, want \"forbidden\"", reply.Code)
			}
			if !strings.Contains(reply.Error, "live") {
				t.Errorf("refusal %q does not name the environment the credential addresses", reply.Error)
			}
		})
	}
}

// TestSandboxInboxFiltersAndPages checks the query parameters a harness polls with:
// the two filters, the page limit, and the total that tells a caller whether more
// messages exist beyond the page it asked for.
func TestSandboxInboxFiltersAndPages(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const (
		first  = "sandbox_filter_one@example.com"
		second = "sandbox_filter_two@example.com"
	)
	for _, address := range []string{first, second} {
		if resp := env.signUp(t, address, "SecurePass123!", "Filter Tester"); resp.status != http.StatusCreated {
			t.Fatalf("signup for %s: got status %d, want 201; body %s", address, resp.status, resp.body)
		}
	}

	list := func(t *testing.T, query string) inboxListing {
		t.Helper()
		resp := env.do(t, http.MethodGet, sandboxInboxPath+query, nil, withSecretKey())
		if resp.status != http.StatusOK {
			t.Fatalf("listing %q: got status %d, want 200; body %s", query, resp.status, resp.body)
		}
		var listing inboxListing
		resp.json(t, &listing)
		return listing
	}

	t.Run("recipient filter", func(t *testing.T) {
		listing := list(t, "?recipient="+first)
		if listing.Total != 1 {
			t.Fatalf("filtering to %s matched %d message(s), want 1", first, listing.Total)
		}
		if listing.Messages[0].Recipient != first {
			t.Errorf("filtered listing returned a message for %q, want %q",
				listing.Messages[0].Recipient, first)
		}
	})

	t.Run("channel filter", func(t *testing.T) {
		if listing := list(t, "?channel=email"); listing.Total != 2 {
			t.Errorf("channel=email matched %d message(s), want 2", listing.Total)
		}
		// Both signups mailed; neither texted.
		if listing := list(t, "?channel=sms"); listing.Total != 0 {
			t.Errorf("channel=sms matched %d message(s), want 0", listing.Total)
		}
	})

	t.Run("page limit reports the full total", func(t *testing.T) {
		listing := list(t, "?limit=1")
		if len(listing.Messages) != 1 {
			t.Errorf("limit=1 returned %d message(s), want 1", len(listing.Messages))
		}
		// A poller waiting for a message cannot learn this from the page length.
		if listing.Total != 2 {
			t.Errorf("limit=1 reported total %d, want the 2 matching before paging", listing.Total)
		}
	})

	t.Run("rejects unparseable parameters", func(t *testing.T) {
		bad := []string{"?channel=carrier-pigeon", "?limit=soon", "?offset=later"}
		for _, query := range bad {
			resp := env.do(t, http.MethodGet, sandboxInboxPath+query, nil, withSecretKey())
			if resp.status != http.StatusBadRequest {
				t.Errorf("listing %q: got status %d, want 400; body %s", query, resp.status, resp.body)
				continue
			}
			var reply errorReply
			resp.json(t, &reply)
			if reply.Code != "validation_failed" {
				t.Errorf("listing %q: refusal code is %q, want \"validation_failed\"", query, reply.Code)
			}
		}
	})
}

// TestSandboxPurgeEmptiesOnlyTheCallersInbox empties one tenant's inbox while
// another tenant holds a capture of its own.
//
// Purge states its tenant and environment predicates itself rather than relying on
// the interceptor alone, and this is the assertion that the belt and the braces are
// both doing something.
func TestSandboxPurgeEmptiesOnlyTheCallersInbox(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)
	env.captureFor(t, victimTenant, "victim_inbox@example.com")

	const address = "sandbox_purge@example.com"
	if resp := env.signUp(t, address, "SecurePass123!", "Purge Tester"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	resp := env.do(t, http.MethodDelete, sandboxInboxPath, nil, withSecretKey())
	if resp.status != http.StatusOK {
		t.Fatalf("purging the inbox: got status %d, want 200; body %s", resp.status, resp.body)
	}

	var purged purgeReply
	resp.json(t, &purged)
	if purged.Removed != 1 {
		t.Errorf("purge removed %d message(s), want the 1 in the caller's inbox", purged.Removed)
	}
	if purged.Environment != testEnvironment {
		t.Errorf("purge reports environment %q, want %q", purged.Environment, testEnvironment)
	}

	if remaining := env.inboxCount(t, testTenant); remaining != 0 {
		t.Errorf("the caller's inbox still holds %d message(s) after a purge", remaining)
	}
	if remaining := env.inboxCount(t, victimTenant); remaining != 1 {
		t.Errorf("the second tenant's inbox holds %d message(s) after another tenant's purge, want 1", remaining)
	}
}

// TestSandboxReadRefusesAnotherTenantsMessage asks for a capture by an ID that
// exists, in a tenant the credential does not reach.
//
// The answer is 404 rather than 403, because telling the caller the ID exists
// somewhere is itself the disclosure.
func TestSandboxReadRefusesAnotherTenantsMessage(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)
	victimMessageID := env.captureFor(t, victimTenant, "victim_read@example.com")

	resp := env.do(t, http.MethodGet, sandboxInboxPath+"/"+victimMessageID, nil, withSecretKey())
	if resp.status != http.StatusNotFound {
		t.Fatalf("reading another tenant's capture: got status %d, want 404; body %s", resp.status, resp.body)
	}

	var reply errorReply
	resp.json(t, &reply)
	if reply.Code != "not_found" {
		t.Errorf("refusal code is %q, want \"not_found\"", reply.Code)
	}
	if strings.Contains(reply.Error, victimMessageID) {
		t.Errorf("refusal %q echoes the message ID, confirming it exists", reply.Error)
	}

	// The row is still there; it was hidden, not deleted.
	if remaining := env.inboxCount(t, victimTenant); remaining != 1 {
		t.Errorf("the second tenant's inbox holds %d message(s) after a refused read, want 1", remaining)
	}
}

// TestDeliveryVerificationRejectsAnUnknownChannel checks the channel validation,
// which runs before the operator is resolved and so is reachable with the secret
// key alone.
func TestDeliveryVerificationRejectsAnUnknownChannel(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.do(t, http.MethodPost, deliveryVerifyPath,
		map[string]string{"channel": "carrier-pigeon"}, withSecretKey())
	if resp.status != http.StatusBadRequest {
		t.Fatalf("verifying an unknown channel: got status %d, want 400; body %s", resp.status, resp.body)
	}

	var reply errorReply
	resp.json(t, &reply)
	if reply.Code != "validation_failed" {
		t.Errorf("refusal code is %q, want \"validation_failed\"", reply.Code)
	}
}

// TestDeliveryVerificationRefusesASecretKey presents the backend credential to the
// one admin route that will not take it.
//
// A secret key names an application rather than a person, so there is no address
// behind it the engine has seen anybody prove control of — and the endpoint's whole
// safety property is that the recipient is not something a caller supplies.
func TestDeliveryVerificationRefusesASecretKey(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	resp := env.do(t, http.MethodPost, deliveryVerifyPath,
		map[string]string{"channel": "email"}, withSecretKey())
	if resp.status != http.StatusForbidden {
		t.Fatalf("verifying delivery with a secret key: got status %d, want 403; body %s",
			resp.status, resp.body)
	}

	var reply errorReply
	resp.json(t, &reply)
	if reply.Code != "forbidden" {
		t.Errorf("refusal code is %q, want \"forbidden\"", reply.Code)
	}
	if !strings.Contains(reply.Error, "console session") {
		t.Errorf("refusal %q does not say which credential the route needs", reply.Error)
	}
}

// TestDeliveryVerificationSendsThroughTheProvider drives the endpoint that
// deliberately bypasses the sandbox, on a console session.
//
// Three properties are asserted together, because each one is what makes the other
// two safe: the message reaches the provider rather than the inbox, the recipient
// is the operator's own stored address, and an address named in the request body
// changes nothing.
func TestDeliveryVerificationSendsThroughTheProvider(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const (
		operatorID = "usr_delivery_operator"
		address    = "delivery_operator@example.com"
	)
	env.seedUser(t, testTenant, operatorID, address)
	session := env.withConsoleSession(t, operatorID, address)

	// An operator who has not proved control of their own address cannot use it to
	// test a provider, which is the same rule the rest of the engine applies to an
	// unverified address.
	resp := env.do(t, http.MethodPost, deliveryVerifyPath, map[string]string{"channel": "email"}, session)
	if resp.status != http.StatusForbidden {
		t.Fatalf("verifying to an unverified address: got status %d, want 403; body %s",
			resp.status, resp.body)
	}
	var refusal errorReply
	resp.json(t, &refusal)
	if refusal.Code != "email_verification_required" {
		t.Errorf("refusal code is %q, want \"email_verification_required\"", refusal.Code)
	}

	env.markEmailVerified(t, operatorID)

	// A recipient in the body is not part of the request shape, so this asks whether
	// the field is absent by construction or merely unused.
	resp = env.do(t, http.MethodPost, deliveryVerifyPath, map[string]string{
		"channel":   "email",
		"recipient": "attacker@example.com",
	}, session)
	if resp.status != http.StatusOK {
		t.Fatalf("verifying email delivery: got status %d, want 200; body %s", resp.status, resp.body)
	}

	var accepted deliveryReply
	resp.json(t, &accepted)
	if accepted.Channel != "email" {
		t.Errorf("reply reports channel %q, want \"email\"", accepted.Channel)
	}
	if accepted.Recipient != address {
		t.Errorf("reply reports recipient %q, want the operator's own address %q", accepted.Recipient, address)
	}
	if accepted.Driver != env.cfg.EmailDriver {
		t.Errorf("reply reports driver %q, want the configured %q", accepted.Driver, env.cfg.EmailDriver)
	}

	delivered := env.emails.messagesTo(address)
	if len(delivered) != 1 {
		t.Fatalf("%d message(s) reached the provider, want 1; a verification that gets captured verifies nothing",
			len(delivered))
	}
	if !strings.Contains(delivered[0].subject, "delivery test") {
		t.Errorf("the delivered message's subject is %q, which is not the delivery test", delivered[0].subject)
	}
	if env.inboxCount(t, testTenant) != 0 {
		t.Error("the delivery test was captured into the sandbox inbox, so it never reached a provider")
	}
	if reached := env.emails.messagesTo("attacker@example.com"); len(reached) != 0 {
		t.Errorf("%d message(s) reached the address named in the request body", len(reached))
	}
}

// TestDeliveryVerificationOverSMS covers the SMS half, whose precondition is a
// verified number on the operator's own account rather than a verified address.
func TestDeliveryVerificationOverSMS(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const (
		operatorID = "usr_sms_operator"
		address    = "sms_operator@example.com"
		number     = "+15550100200"
	)
	env.seedUser(t, testTenant, operatorID, address)
	session := env.withConsoleSession(t, operatorID, address)

	resp := env.do(t, http.MethodPost, deliveryVerifyPath, map[string]string{"channel": "sms"}, session)
	if resp.status != http.StatusForbidden {
		t.Fatalf("verifying SMS with no phone number on file: got status %d, want 403; body %s",
			resp.status, resp.body)
	}
	var refusal errorReply
	resp.json(t, &refusal)
	if !strings.Contains(refusal.Error, "phone number") {
		t.Errorf("refusal %q does not say what the account is missing", refusal.Error)
	}

	env.setVerifiedPhone(t, operatorID, number)

	resp = env.do(t, http.MethodPost, deliveryVerifyPath, map[string]string{"channel": "sms"}, session)
	if resp.status != http.StatusOK {
		t.Fatalf("verifying SMS delivery: got status %d, want 200; body %s", resp.status, resp.body)
	}

	var accepted deliveryReply
	resp.json(t, &accepted)
	if accepted.Channel != "sms" {
		t.Errorf("reply reports channel %q, want \"sms\"", accepted.Channel)
	}
	if accepted.Recipient != number {
		t.Errorf("reply reports recipient %q, want the operator's own number %q", accepted.Recipient, number)
	}

	texted := env.texts.messagesTo(number)
	if len(texted) != 1 {
		t.Fatalf("%d text message(s) reached the provider, want 1", len(texted))
	}
	if env.inboxCount(t, testTenant) != 0 {
		t.Error("the SMS delivery test was captured into the sandbox inbox, so it never reached a provider")
	}
}
