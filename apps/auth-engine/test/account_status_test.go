//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/account_status_test.go
 * Tier: Integration Tests / Account Status Enforcement
 *
 * Covers the gate that refuses a restricted account at every path that mints a
 * token: password login, the two refresh endpoints, and magic-link verification.
 *
 * These are the assertions that make a ban mean something. The status column
 * existed before the gate did, and every one of these paths read a user row and
 * issued a token without consulting it, so each test here corresponds to a way an
 * account could previously be signed into after it was banned.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"testing"
	"time"

	entuser "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// errorReply is the flat error envelope every handler answers with. The code is
// the contract a client branches on, so the tests assert on it rather than on the
// prose, which is free to change.
type errorReply struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// codeAccountDisabled is the wire code for a refusal on eligibility grounds. A
// client shows a contact-support path on it rather than a retry prompt.
const codeAccountDisabled = "account_disabled"

// setStatus writes a user's status directly.
//
// Nothing in the engine writes this column yet — the admin actions that will are
// a separate endpoint surface — so the restriction is applied the way an operator
// or a migration would, and the test observes what the auth paths then do with it.
func (e *testEnv) setStatus(t *testing.T, address string, status entuser.Status) {
	t.Helper()
	ctx := e.bypassContext()
	n, err := e.client(ctx).User.Update().
		Where(entuser.EmailEQ(address)).
		SetStatus(status).
		Save(ctx)
	if err != nil {
		t.Fatalf("setting %s to %s: %v", address, status, err)
	}
	if n != 1 {
		t.Fatalf("setting %s to %s updated %d rows, want 1", address, status, n)
	}
}

// softDelete stamps deleted_at, which is how an erased account is represented: the
// row stays behind to keep the address reserved.
func (e *testEnv) softDelete(t *testing.T, address string) {
	t.Helper()
	ctx := e.bypassContext()
	n, err := e.client(ctx).User.Update().
		Where(entuser.EmailEQ(address)).
		SetDeletedAt(time.Now()).
		Save(ctx)
	if err != nil {
		t.Fatalf("soft-deleting %s: %v", address, err)
	}
	if n != 1 {
		t.Fatalf("soft-deleting %s updated %d rows, want 1", address, n)
	}
}

// assertRefusedAsDisabled checks a reply is the eligibility refusal and not some
// other 403. A wrong code here is a real defect: the SDK routes the user to
// support on this one and to a retry on the others.
func assertRefusedAsDisabled(t *testing.T, label string, resp response) {
	t.Helper()
	if resp.status != http.StatusForbidden {
		t.Fatalf("%s: got status %d, want 403; body %s", label, resp.status, resp.body)
	}
	var reply errorReply
	resp.json(t, &reply)
	if reply.Code != codeAccountDisabled {
		t.Errorf("%s: got code %q, want %q; body %s", label, reply.Code, codeAccountDisabled, resp.body)
	}
	if reply.Error == "" {
		t.Errorf("%s: refusal carried no message for the account holder", label)
	}
}

// TestPasswordLoginRefusesRestrictedAccounts is the primary gate. Each status is
// driven through a real sign-in with the correct password, because the whole point
// is that a correct credential is no longer sufficient.
func TestPasswordLoginRefusesRestrictedAccounts(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	const password = "SuperSecret123!"

	restricted := []struct {
		name   string
		status entuser.Status
	}{
		{"banned", entuser.StatusBanned},
		{"suspended", entuser.StatusSuspended},
		{"recovery hold", entuser.StatusRecoveryHold},
	}

	for _, tc := range restricted {
		t.Run(tc.name, func(t *testing.T) {
			address := string(tc.status) + "_login@example.com"
			if resp := env.signUp(t, address, password, "Restricted User"); resp.status != http.StatusCreated {
				t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
			}
			env.setStatus(t, address, tc.status)

			assertRefusedAsDisabled(t, tc.name+" login", env.login(t, address, password))
		})
	}

	// A soft-deleted account is deliberately indistinguishable from an unknown
	// address. Its row exists only to keep the address reserved, so naming it would
	// turn the login form into a way to ask which addresses were once registered.
	t.Run("soft deleted reads as unknown", func(t *testing.T) {
		const address = "erased_login@example.com"
		if resp := env.signUp(t, address, password, "Erased User"); resp.status != http.StatusCreated {
			t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
		}
		env.softDelete(t, address)

		resp := env.login(t, address, password)
		if resp.status != http.StatusUnauthorized {
			t.Fatalf("soft-deleted login: got status %d, want 401; body %s", resp.status, resp.body)
		}
		var reply errorReply
		resp.json(t, &reply)
		if reply.Code == codeAccountDisabled {
			t.Errorf("soft-deleted login answered %q, disclosing that the address was once registered", reply.Code)
		}
	})

	// The positive control. Without it every assertion above would still pass if
	// the gate refused everyone.
	t.Run("active account still signs in", func(t *testing.T) {
		const address = "active_login@example.com"
		if resp := env.signUp(t, address, password, "Active User"); resp.status != http.StatusCreated {
			t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
		}
		if resp := env.login(t, address, password); resp.status != http.StatusOK {
			t.Fatalf("active login: got status %d, want 200; body %s", resp.status, resp.body)
		}
	})
}

// TestRestrictionEndsAnEstablishedSession covers the case a login gate alone does
// not: the account was already signed in when the restriction landed. Both refresh
// endpoints have to refuse, since either one on its own would keep the session
// renewing indefinitely.
func TestRestrictionEndsAnEstablishedSession(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	const password = "SuperSecret123!"

	// The harness wires no Redis, so the middleware's issued-at cutoff is inert
	// here and the access token already in the caller's hand stays valid until it
	// expires. That is the bound the cutoff exists to shorten, and it is covered by
	// the tokenblocklist unit tests; what these assertions pin is that the session
	// itself cannot be renewed, which is what makes the restriction permanent.
	t.Run("client refresh endpoint", func(t *testing.T) {
		const address = "banned_client_refresh@example.com"
		if resp := env.signUp(t, address, password, "Session User"); resp.status != http.StatusCreated {
			t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
		}
		loginResp := env.login(t, address, password)
		if loginResp.status != http.StatusOK {
			t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
		}
		superseded := loginResp.cookie(refreshCookieName)
		if superseded == nil {
			t.Fatalf("login did not set the %s cookie", refreshCookieName)
		}

		// Refresh works while the account is active, so the failures below are
		// attributable to the restriction and not to the request being malformed.
		rotateResp := env.do(t, http.MethodPost, "/v1/client/auth/refresh", nil, withCookie(superseded))
		if rotateResp.status != http.StatusOK {
			t.Fatalf("refresh while active: got status %d, want 200; body %s", rotateResp.status, rotateResp.body)
		}
		live := rotateResp.cookie(refreshCookieName)
		if live == nil {
			t.Fatalf("refresh did not set a replacement %s cookie", refreshCookieName)
		}

		env.setStatus(t, address, entuser.StatusBanned)

		// The live token, against the session row that is still active. This is the
		// ordinary path a client takes every time its access token ages out.
		assertRefusedAsDisabled(t, "refresh after ban",
			env.do(t, http.MethodPost, "/v1/client/auth/refresh", nil, withCookie(live)))

		// The superseded token, inside its grace window. Separate branch, and the one
		// that would otherwise hand a banned account a token and then log a theft
		// alert for the ordinary retry that produced it.
		assertRefusedAsDisabled(t, "grace-window replay after ban",
			env.do(t, http.MethodPost, "/v1/client/auth/refresh", nil, withCookie(superseded)))
	})

	t.Run("oauth token endpoint refresh grant", func(t *testing.T) {
		const address = "banned_oauth_refresh@example.com"
		if resp := env.signUp(t, address, password, "OAuth Session User"); resp.status != http.StatusCreated {
			t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
		}
		loginResp := env.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
		if loginResp.status != http.StatusOK {
			t.Fatalf("native login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
		}
		var loggedIn tokenResponse
		loginResp.json(t, &loggedIn)
		if loggedIn.RefreshToken == "" {
			t.Fatalf("native login returned no refresh token; body %s", loginResp.body)
		}

		env.setStatus(t, address, entuser.StatusSuspended)

		assertRefusedAsDisabled(t, "oauth refresh after suspension",
			env.do(t, http.MethodPost, "/v1/oauth/token", refreshRequest{
				GrantType:    "refresh_token",
				RefreshToken: loggedIn.RefreshToken,
			}))
	})

	// The OAuth endpoint's own grace window, which is a separate branch from the
	// client endpoint's. It is reached by replaying a token that has already been
	// rotated, so the restriction has to be applied while the account was active
	// long enough for the rotation to happen.
	t.Run("oauth token endpoint grace window", func(t *testing.T) {
		const address = "banned_oauth_grace@example.com"
		if resp := env.signUp(t, address, password, "OAuth Grace User"); resp.status != http.StatusCreated {
			t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
		}
		loginResp := env.login(t, address, password, withHeader("X-Authn-Client-Type", "native"))
		if loginResp.status != http.StatusOK {
			t.Fatalf("native login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
		}
		var loggedIn tokenResponse
		loginResp.json(t, &loggedIn)

		rotateResp := env.do(t, http.MethodPost, "/v1/oauth/token", refreshRequest{
			GrantType:    "refresh_token",
			RefreshToken: loggedIn.RefreshToken,
		})
		if rotateResp.status != http.StatusOK {
			t.Fatalf("oauth refresh while active: got status %d, want 200; body %s",
				rotateResp.status, rotateResp.body)
		}

		env.setStatus(t, address, entuser.StatusBanned)

		assertRefusedAsDisabled(t, "oauth grace-window replay after ban",
			env.do(t, http.MethodPost, "/v1/oauth/token", refreshRequest{
				GrantType:    "refresh_token",
				RefreshToken: loggedIn.RefreshToken,
			}))
	})
}

// TestRefusedMagicLinkIsNotSpent pins where the gate sits rather than just that it
// exists. Verification consumes the token, so a gate placed after the consumption
// would refuse the attempt and destroy the link with it — and the account holder,
// once reinstated, would be left holding a link that no longer works and no
// explanation for why.
func TestRefusedMagicLinkIsNotSpent(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	const address = "magic_restricted@example.com"

	requestMagicLink(t, env, address)
	token, ok := env.emails.tokenFor(address)
	if !ok {
		t.Fatalf("no magic-link email carrying a token was sent to %s", address)
	}

	env.setStatus(t, address, entuser.StatusSuspended)

	assertRefusedAsDisabled(t, "magic-link verify while suspended",
		env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify",
			map[string]string{"token": token}))

	env.setStatus(t, address, entuser.StatusActive)

	resp := env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify",
		map[string]string{"token": token})
	if resp.status != http.StatusOK {
		t.Fatalf("magic-link verify after reinstatement: got status %d, want 200; "+
			"the refused attempt consumed the link; body %s", resp.status, resp.body)
	}
}

// TestSoftDeletedAddressStaysReserved covers the reason a deleted account keeps a
// row at all. Re-registering the address has to be refused, or the next person to
// claim it inherits whatever the old account is still referenced by.
func TestSoftDeletedAddressStaysReserved(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	const address = "reserved@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "Original Owner"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}
	env.softDelete(t, address)

	if resp := env.signUp(t, address, "DifferentSecret456!", "New Claimant"); resp.status != http.StatusConflict {
		t.Fatalf("re-signup on a soft-deleted address: got status %d, want 409; body %s",
			resp.status, resp.body)
	}

	// A magic link is the other way to arrive at an address without a password. It
	// provisions unknown addresses, so it must not provision this one back into use.
	requestMagicLink(t, env, address)
	if token, ok := env.emails.tokenFor(address); ok {
		resp := env.do(t, http.MethodPost, "/v1/client/auth/magic-link/verify",
			map[string]string{"token": token})
		if resp.status == http.StatusOK {
			t.Errorf("a magic link signed into a soft-deleted account; body %s", resp.body)
		}
	}
}

// TestAccessTokensCarrySessionID guards a claim the session routes depend on. A
// token without sid cannot name its own session, so ListSessions cannot mark the
// current one and RevokeOtherSessions treats the caller's own session as another
// one — signing the caller out of the request they are making.
func TestAccessTokensCarrySessionID(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	const password = "SuperSecret123!"

	cases := []struct {
		name    string
		address string
		issue   func(t *testing.T, address string) response
	}{
		{
			name:    "signup",
			address: "sid_signup@example.com",
			issue: func(t *testing.T, address string) response {
				return env.signUp(t, address, password, "Signup Sid User")
			},
		},
		{
			name:    "login",
			address: "sid_login@example.com",
			issue: func(t *testing.T, address string) response {
				if resp := env.signUp(t, address, password, "Login Sid User"); resp.status != http.StatusCreated {
					t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
				}
				return env.login(t, address, password)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.issue(t, tc.address)
			if resp.status != http.StatusOK && resp.status != http.StatusCreated {
				t.Fatalf("%s: got status %d, want 200 or 201; body %s", tc.name, resp.status, resp.body)
			}

			var reply magicLinkReply
			resp.json(t, &reply)
			if reply.AccessToken == "" {
				t.Fatalf("%s returned no access token; body %s", tc.name, resp.body)
			}

			claims, err := jwtpkg.VerifyAccessToken(reply.AccessToken, env.cfg.EncryptionKey)
			if err != nil {
				t.Fatalf("verifying the %s access token: %v", tc.name, err)
			}
			if claims.SessionID == "" {
				t.Errorf("the %s access token carries no sid claim, so it cannot identify its own session", tc.name)
			}
		})
	}
}
