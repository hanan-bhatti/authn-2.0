//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/metadata_reserved_keys_test.go
 * Tier: Integration Test
 *
 * Covers the boundary between the two owners of one metadata bag: the caller's own
 * attributes, and the engine's pending-verification state. Nothing in the database
 * separates them, so the separation is a list of reserved keys refused on write and
 * stripped from every read.
 *
 * The write half is what closes an account takeover. VerifyEmailChange matches a
 * presented token against a digest held in that bag, so a caller able to write the
 * digest can present the matching token and have any address recorded as its verified
 * primary with nothing ever sent to it. A verified address satisfies every check that
 * reads verification as proof of control — the invitation inbox included.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	entuser "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

// profileReply is the subset of the profile response these tests assert on.
type profileReply struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// forgedVerificationMetadata is the payload of the takeover: an address the caller
// does not hold, the digest of a token the caller chose, and an expiry far enough out
// to stay valid.
//
// It is built from the same token the test later presents, so the pair really would
// verify. A fixture whose digest did not match its token would pass the assertions
// below without the refusal doing any work.
func forgedVerificationMetadata(token, targetAddress string) map[string]interface{} {
	digest := sha256.Sum256([]byte(token))
	return map[string]interface{}{
		"pending_new_email":        targetAddress,
		"pending_email_token_hash": hex.EncodeToString(digest[:]),
		"pending_email_expires_at": time.Now().Add(time.Hour).Unix(),
	}
}

// accessTokenFor signs an account in and returns a bearer token for it.
func (e *testEnv) accessTokenFor(t *testing.T, address, password string) string {
	t.Helper()

	resp := e.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
	if resp.status != http.StatusOK {
		t.Fatalf("login as %s: got status %d, want 200; body %s", address, resp.status, resp.body)
	}
	var tokens tokenResponse
	resp.json(t, &tokens)
	if tokens.AccessToken == "" {
		t.Fatalf("login as %s returned no access token: %s", address, resp.body)
	}
	return tokens.AccessToken
}

// storedMetadata reads an account's metadata bag straight from the database, past the
// read filter, which is the only way to see whether a refused write left anything
// behind.
func (e *testEnv) storedMetadata(t *testing.T, address string) map[string]interface{} {
	t.Helper()

	ctx := e.bypassContext()
	u, err := e.client(ctx).User.Query().
		Where(entuser.EmailEQ(strings.ToLower(address))).
		Only(ctx)
	if err != nil {
		t.Fatalf("loading %s: %v", address, err)
	}
	return u.Metadata
}

// TestProfilePatchRefusesForgedEmailVerificationState is the takeover attempt, run
// end to end against the route a browser can reach.
func TestProfilePatchRefusesForgedEmailVerificationState(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "metadata.attacker@example.com"
	const password = "SecurePass123!"
	const target = "ceo@victim-corp.example"
	const chosenToken = "a-token-the-caller-picked-itself"

	if resp := env.signUp(t, address, password, "Metadata Attacker"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}
	accessToken := env.accessTokenFor(t, address, password)

	resp := env.do(t, http.MethodPatch, "/v1/client/user/profile", map[string]any{
		"metadata": forgedVerificationMetadata(chosenToken, target),
	}, withHeader("Authorization", "Bearer "+accessToken))
	assertRefusedWith(t, "patching forged verification state", resp, http.StatusUnprocessableEntity, "validation_failed")

	// The refusal has to name the key. A caller told only that something was reserved
	// has to guess which of its own keys to drop.
	if !strings.Contains(string(resp.body), "pending_") {
		t.Errorf("refusal did not name the reserved key it rejected: %s", resp.body)
	}

	// Nothing may be left in the bag. A partial merge would leave the digest in place
	// for the next request to complete.
	for key := range forgedVerificationMetadata(chosenToken, target) {
		if _, present := env.storedMetadata(t, address)[key]; present {
			t.Fatalf("refused write still stored %q", key)
		}
	}

	// The exploit's second half, attempted anyway: without the digest, the token the
	// caller chose matches no account.
	verifyResp := env.do(t, http.MethodGet,
		"/v1/client/user/email/verify?token="+url.QueryEscape(chosenToken), nil)
	if verifyResp.status == http.StatusOK {
		t.Fatalf("a self-chosen token verified an email change: %s", verifyResp.body)
	}

	// And the account still holds the address it signed up with, unchanged and — since
	// no link was followed — still unverified.
	ctx := env.bypassContext()
	u, err := env.client(ctx).User.Query().Where(entuser.EmailEQ(address)).Only(ctx)
	if err != nil {
		t.Fatalf("reloading %s: %v", address, err)
	}
	if u.Email != address {
		t.Fatalf("primary email became %q; the takeover succeeded", u.Email)
	}
	if u.EmailVerified {
		t.Fatal("account reported email_verified=true without any link being followed")
	}
}

// TestProfilePatchAcceptsOrdinaryMetadata is the positive control for the test above.
//
// Without it, a PATCH broken for every payload would pass the refusal assertions
// while proving nothing about reserved keys in particular.
func TestProfilePatchAcceptsOrdinaryMetadata(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "metadata.ordinary@example.com"
	const password = "SecurePass123!"

	if resp := env.signUp(t, address, password, "Ordinary Metadata"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}
	accessToken := env.accessTokenFor(t, address, password)

	resp := env.do(t, http.MethodPatch, "/v1/client/user/profile", map[string]any{
		"metadata": map[string]any{"plan_tier": "growth", "seat_count": 12},
	}, withHeader("Authorization", "Bearer "+accessToken))
	assertStatus(t, "patching ordinary metadata", resp, http.StatusOK)

	read := env.do(t, http.MethodGet, "/v1/client/user/profile", nil,
		withHeader("Authorization", "Bearer "+accessToken))
	assertStatus(t, "reading profile", read, http.StatusOK)

	var profile profileReply
	read.json(t, &profile)
	if profile.Metadata["plan_tier"] != "growth" {
		t.Fatalf("caller metadata did not survive the round trip: %v", profile.Metadata)
	}
}

// TestProfileReadOmitsEngineVerificationState checks the read half.
//
// The state is planted by the engine's own route rather than written directly, so the
// assertion covers the shape a real pending change leaves behind.
func TestProfileReadOmitsEngineVerificationState(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "metadata.reader@example.com"
	const password = "SecurePass123!"

	if resp := env.signUp(t, address, password, "Metadata Reader"); resp.status != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", resp.status, resp.body)
	}
	accessToken := env.accessTokenFor(t, address, password)

	// A genuine pending email change, which is what writes the digest and the expiry.
	change := env.do(t, http.MethodPost, "/v1/client/user/email", map[string]string{
		"new_email": "metadata.reader.new@example.com",
	}, withHeader("Authorization", "Bearer "+accessToken))
	assertStatus(t, "requesting an email change", change, http.StatusOK)

	// Present in the row: the engine needs it to complete the change.
	stored := env.storedMetadata(t, address)
	if _, present := stored["pending_email_token_hash"]; !present {
		t.Fatal("an accepted email change wrote no token digest, so this test would pass vacuously")
	}

	read := env.do(t, http.MethodGet, "/v1/client/user/profile", nil,
		withHeader("Authorization", "Bearer "+accessToken))
	assertStatus(t, "reading profile", read, http.StatusOK)

	// Absent from the reply: a digest handed to whoever holds the session is a digest
	// handed to whoever borrowed it, and the matching token verifies the change.
	var profile profileReply
	read.json(t, &profile)
	for _, key := range []string{"pending_new_email", "pending_email_token_hash", "pending_email_expires_at"} {
		if _, leaked := profile.Metadata[key]; leaked {
			t.Errorf("profile response exposed engine state %q: %s", key, read.body)
		}
	}
}

// TestAdminPatchRefusesForgedEmailVerificationState holds the administrative surface
// to the same rule.
//
// An operator has legitimate routes for changing a user's address. Forging the digest
// that proves the user confirmed it is not one of them, and it is the one forgery an
// audit trail of administrative changes cannot tell apart from a real confirmation.
func TestAdminPatchRefusesForgedEmailVerificationState(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	userID := env.registerUser(t, "metadata.admin.target@example.com", "Admin Target")

	resp := env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID, map[string]any{
		"metadata": forgedVerificationMetadata("operator-chosen-token", "attacker@example.net"),
	})
	assertRefusedWith(t, "admin patching forged verification state", resp, http.StatusUnprocessableEntity, "validation_failed")

	// Positive control on the same route: an ordinary key goes through, so the refusal
	// above is about the key and not about the route being broken.
	ok := env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID, map[string]any{
		"metadata": map[string]any{"support_notes": "verified by phone"},
	})
	assertStatus(t, "admin patching ordinary metadata", ok, http.StatusOK)
}

// TestAdminUserReadOmitsEngineVerificationState checks the administrative read.
//
// Security-question answers live in the same bag and are low-entropy enough that a
// digest shown in a console is close to the answer itself.
func TestAdminUserReadOmitsEngineVerificationState(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "metadata.admin.reader@example.com"
	userID := env.registerUser(t, address, "Admin Reader")

	// Planted directly: this is state no administrative route creates, and the point is
	// that the read filter covers it wherever it came from.
	ctx := env.bypassContext()
	if err := env.client(ctx).User.UpdateOneID(userID).SetMetadata(map[string]interface{}{
		"recovery_email":          "backup@example.com",
		"recovery_email_verified": true,
		"security_questions": []interface{}{
			map[string]interface{}{"id": "sq_1", "question": "First pet?", "answer_hash": "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA"},
		},
		"support_notes": "kept",
	}).Exec(ctx); err != nil {
		t.Fatalf("planting metadata: %v", err)
	}

	resp := env.admin(t, http.MethodGet, "/v1/admin/users/"+userID, nil)
	assertStatus(t, "admin reading a user", resp, http.StatusOK)

	body := string(resp.body)
	for _, key := range []string{"recovery_email_verified", "security_questions", "answer_hash", "$argon2id"} {
		if strings.Contains(body, key) {
			t.Errorf("admin user response exposed engine state %q: %s", key, body)
		}
	}
	// The operator's own note is not engine state and must survive, or the filter is
	// dropping more than it should.
	if !strings.Contains(body, "support_notes") {
		t.Errorf("admin user response dropped a caller attribute: %s", body)
	}
}
