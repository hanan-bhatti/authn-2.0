/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/signer_test.go
 * Tier: Shared Package / Tests
 *
 * Description: Tests that an access token's signed expiry is the lifetime the
 *              caller asked for, so the `expires_in` an API advertises and the
 *              `exp` a client enforces cannot disagree.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package jwt

import (
	"testing"
	"time"
)

const signerTestSecret = "signer-test-secret-value-32-bytes!!!"

// TestIssueAccessTokenHonoursTTL is the guard against the API describing a
// token it did not sign.
//
// A caller reports `expires_in` from its configured lifetime. If the signer
// applied a lifetime of its own, a deployment that shortened the setting would
// advertise the short value while minting long-lived tokens — the client
// refreshes early and the real exposure window is whatever the signer chose.
func TestIssueAccessTokenHonoursTTL(t *testing.T) {
	for _, ttl := range []time.Duration{time.Minute, 5 * time.Minute, time.Hour, 24 * time.Hour} {
		t.Run(ttl.String(), func(t *testing.T) {
			issuedAt := time.Now().UTC()

			token, err := IssueAccessToken(
				"usr_1", "tnt_1", "test", "a@example.com", "A", "", signerTestSecret, ttl)
			if err != nil {
				t.Fatalf("IssueAccessToken: %v", err)
			}

			claims, err := VerifyAccessToken(token, signerTestSecret)
			if err != nil {
				t.Fatalf("VerifyAccessToken: %v", err)
			}

			gotLifetime := time.Unix(claims.Exp, 0).Sub(issuedAt)
			// One second of slack absorbs the boundary between issuing and
			// reading the clock; anything larger is the signer substituting its
			// own lifetime.
			if diff := gotLifetime - ttl; diff > time.Second || diff < -time.Second {
				t.Errorf("signed lifetime = %s, want %s (the token outlives what a caller would advertise)",
					gotLifetime, ttl)
			}
		})
	}
}

// The session-carrying variant signs the same claim set, so it must honour the
// lifetime identically.
func TestIssueAccessTokenWithSessionHonoursTTL(t *testing.T) {
	issuedAt := time.Now().UTC()
	const ttl = 3 * time.Minute

	token, err := IssueAccessTokenWithSession(
		"usr_2", "tnt_1", "test", "b@example.com", "B", "", "ses_2", signerTestSecret, ttl)
	if err != nil {
		t.Fatalf("IssueAccessTokenWithSession: %v", err)
	}

	claims, err := VerifyAccessToken(token, signerTestSecret)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	if claims.SessionID != "ses_2" {
		t.Errorf("sid = %q, want ses_2", claims.SessionID)
	}
	gotLifetime := time.Unix(claims.Exp, 0).Sub(issuedAt)
	if diff := gotLifetime - ttl; diff > time.Second || diff < -time.Second {
		t.Errorf("signed lifetime = %s, want %s", gotLifetime, ttl)
	}
}

// A non-positive lifetime means the caller had no configured value. Signing a
// token that has already expired would break every login, so the built-in
// default applies instead.
func TestIssueAccessTokenRejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		token, err := IssueAccessToken(
			"usr_3", "tnt_1", "test", "c@example.com", "C", "", signerTestSecret, ttl)
		if err != nil {
			t.Fatalf("IssueAccessToken(%s): %v", ttl, err)
		}

		claims, err := VerifyAccessToken(token, signerTestSecret)
		if err != nil {
			t.Fatalf("a token issued with ttl=%s must still verify, got: %v", ttl, err)
		}

		remaining := time.Until(time.Unix(claims.Exp, 0))
		if remaining <= 0 {
			t.Errorf("ttl=%s produced an already-expired token", ttl)
		}
		if diff := remaining - AccessTokenTTL(); diff > time.Second || diff < -time.Second {
			t.Errorf("ttl=%s should fall back to %s, got %s", ttl, AccessTokenTTL(), remaining)
		}
	}
}
