//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/admin_users_test.go
 * Tier: Integration Tests / Administrative User Directory
 *
 * Drives the /v1/admin/users surface through the real admin guard, and checks
 * each action against what it is supposed to accomplish rather than against the
 * status code it returns. A ban is asserted by trying to sign in afterwards; a
 * forced sign-out by trying to refresh; a retirement by both, and then by
 * restoring the account and signing in again.
 *
 * The status-only version of these tests would pass against a handler that
 * answered 200 and wrote nothing, which is the failure worth catching: every
 * endpoint here exists to change whether somebody can get in.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	entuser "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
)

// Wire codes the admin surface answers with. Tests assert on these rather than
// on the prose, which is free to change.
const (
	codeUnauthorized     = "unauthorized"
	codeValidationFailed = "validation_failed"
	codeNotFound         = "not_found"
	codeConflict         = "conflict"
	codeAlreadyExists    = "already_exists"
	// codeSessionRevoked is what a refresh answers once an administrator has ended
	// the session behind it.
	codeSessionRevoked = "session_revoked"
)

// adminPassword is the credential every account in this file signs up with. One
// value throughout keeps a failed sign-in attributable to the account's state
// rather than to the password used.
const adminPassword = "SuperSecret123!"

// adminUserDTO mirrors the fields the directory returns that these tests assert
// on. It is deliberately partial: the projection carries more, and enumerating
// all of it here would make an added field a test failure.
type adminUserDTO struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Username      string                 `json:"username"`
	Name          string                 `json:"name"`
	Status        string                 `json:"status"`
	HasPassword   bool                   `json:"has_password"`
	Locale        string                 `json:"locale"`
	DeletedAt     *string                `json:"deleted_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// adminUserListReply is one page of the directory.
type adminUserListReply struct {
	Users  []adminUserDTO `json:"users"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

// adminUserDetail is one account plus the sign-in surface the detail route adds.
type adminUserDetail struct {
	adminUserDTO
	ActiveSessions  int      `json:"active_sessions"`
	SocialProviders []string `json:"social_providers"`
	TwoFactorTypes  []string `json:"two_factor_types"`
}

// adminLogoutReply is the forced sign-out result.
type adminLogoutReply struct {
	UserID          string `json:"user_id"`
	SessionsRevoked int    `json:"sessions_revoked"`
}

// admin sends a request to the administrative surface carrying the seeded secret
// key, which is the backend credential the guard accepts.
func (e *testEnv) admin(t *testing.T, method, path string, payload any) response {
	t.Helper()
	return e.do(t, method, path, payload, withHeader("X-Authn-Secret-Key", secretKey))
}

// userIDFor returns the stored ID for an address, which is what the admin routes
// address an account by.
func (e *testEnv) userIDFor(t *testing.T, address string) string {
	t.Helper()

	ctx := e.bypassContext()
	u, err := e.client(ctx).User.Query().
		Where(entuser.EmailEQ(strings.ToLower(address))).
		Only(ctx)
	if err != nil {
		t.Fatalf("loading user %s: %v", address, err)
	}
	return u.ID
}

// registerUser signs an account up and returns its ID, failing the test when
// signup itself did not succeed — an assertion about an admin action on a user
// that was never created would be meaningless.
func (e *testEnv) registerUser(t *testing.T, address, name string) string {
	t.Helper()

	if resp := e.signUp(t, address, adminPassword, name); resp.status != http.StatusCreated {
		t.Fatalf("signing up %s: got status %d, want 201; body %s", address, resp.status, resp.body)
	}
	return e.userIDFor(t, address)
}

// assertStatus fails the test unless resp carries the wanted status.
func assertStatus(t *testing.T, label string, resp response, want int) {
	t.Helper()
	if resp.status != want {
		t.Fatalf("%s: got status %d, want %d; body %s", label, resp.status, want, resp.body)
	}
}

// assertRefusedWith fails the test unless resp is the wanted status carrying the
// wanted machine code.
func assertRefusedWith(t *testing.T, label string, resp response, wantStatus int, wantCode string) {
	t.Helper()

	if resp.status != wantStatus {
		t.Fatalf("%s: got status %d, want %d; body %s", label, resp.status, wantStatus, resp.body)
	}
	var reply errorReply
	resp.json(t, &reply)
	if reply.Code != wantCode {
		t.Errorf("%s: got code %q, want %q; body %s", label, reply.Code, wantCode, resp.body)
	}
	if reply.Error == "" {
		t.Errorf("%s: refusal carried no message", label)
	}
}

// emailsOf returns the addresses in a page, in the order the page listed them.
func emailsOf(page adminUserListReply) []string {
	out := make([]string, 0, len(page.Users))
	for _, u := range page.Users {
		out = append(out, u.Email)
	}
	return out
}

// TestAdminSurfaceRefusesNonAdminCredentials pins the boundary the whole surface
// rests on.
//
// The publishable key cases are the ones that matter: it ships in browser
// JavaScript, so if it reached these routes every visitor to a customer's login
// page could ban that customer's users.
func TestAdminSurfaceRefusesNonAdminCredentials(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	victimID := env.registerUser(t, "guard.probe@example.com", "Guard Probe")

	t.Run("no admin credential", func(t *testing.T) {
		// e.do attaches the publishable key and nothing else, which is exactly what
		// a browser holds.
		resp := env.do(t, http.MethodGet, "/v1/admin/users", nil)
		assertRefusedWith(t, "list without an admin credential", resp,
			http.StatusUnauthorized, codeUnauthorized)
	})

	t.Run("publishable key offered as the secret key", func(t *testing.T) {
		resp := env.do(t, http.MethodGet, "/v1/admin/users", nil,
			withHeader("X-Authn-Secret-Key", publishableKey))
		assertRefusedWith(t, "list with a publishable key", resp,
			http.StatusUnauthorized, codeUnauthorized)
	})

	t.Run("a state change is refused too", func(t *testing.T) {
		// The read routes are the obvious target, but the guard has to hold on the
		// routes that write. A read leaks the directory; this one ends an account.
		resp := env.do(t, http.MethodPost, "/v1/admin/users/"+victimID+"/ban", nil)
		assertRefusedWith(t, "ban without an admin credential", resp,
			http.StatusUnauthorized, codeUnauthorized)

		if login := env.login(t, "guard.probe@example.com", adminPassword); login.status != http.StatusOK {
			t.Fatalf("account was affected by a refused ban: login got status %d; body %s",
				login.status, login.body)
		}
	})
}

// TestAdminDirectoryReachesOnlyTheCallersTenant is the isolation assertion for
// this surface: the credential names one tenant, and rows belonging to another
// must be neither listed nor addressable by ID.
//
// The ID case is separate from the listing case on purpose. A handler can filter
// a listing correctly and still fetch by a bare primary key, which is the shape
// of every cross-tenant read this codebase has had.
func TestAdminDirectoryReachesOnlyTheCallersTenant(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedVictimTenant(t)

	const ownAddress = "own.tenant@example.com"
	env.registerUser(t, ownAddress, "Own Tenant User")

	const foreignAddress = "target@victim-tenant.example"
	foreign, err := env.authRepo.CreateUser(env.bypassContext(), "usr_admin_foreign_target",
		victimTenant, testEnvironment, foreignAddress,
		"argon2id$placeholder$hash", "Foreign User", "")
	if err != nil {
		t.Fatalf("seeding foreign user: %v", err)
	}

	t.Run("listing omits the other tenant", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users", nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page adminUserListReply
		resp.json(t, &page)

		for _, address := range emailsOf(page) {
			if strings.EqualFold(address, foreignAddress) {
				t.Fatalf("listing disclosed %s, which belongs to tenant %s", address, victimTenant)
			}
		}
		if page.Total != 1 {
			t.Errorf("total = %d, want 1 — only the caller's own user", page.Total)
		}
	})

	t.Run("fetching the other tenant's user by ID is a 404", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users/"+foreign.ID, nil)
		assertRefusedWith(t, "get foreign user", resp, http.StatusNotFound, codeNotFound)
	})

	t.Run("acting on the other tenant's user is a 404", func(t *testing.T) {
		resp := env.admin(t, http.MethodPost, "/v1/admin/users/"+foreign.ID+"/ban", nil)
		assertRefusedWith(t, "ban foreign user", resp, http.StatusNotFound, codeNotFound)

		after, err := env.factory.GetClient(env.bypassContext(), victimTenant, testEnvironment).
			User.Get(env.bypassContext(), foreign.ID)
		if err != nil {
			t.Fatalf("re-reading foreign user: %v", err)
		}
		if after.Status != entuser.StatusActive {
			t.Fatalf("foreign user status is %s after a refused ban, want active", after.Status)
		}
	})
}

// TestAdminBanStopsSignIn is the core assertion: the endpoint's purpose is that a
// correct password stops working.
func TestAdminBanStopsSignIn(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "ban.target@example.com"
	userID := env.registerUser(t, address, "Ban Target")

	// The positive control. Without it, a ban assertion would also pass against a
	// deployment that refused this account all along.
	assertStatus(t, "login before the ban", env.login(t, address, adminPassword), http.StatusOK)

	resp := env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/ban",
		map[string]string{"reason": "payment fraud"})
	assertStatus(t, "ban", resp, http.StatusOK)

	var banned adminUserDTO
	resp.json(t, &banned)
	if banned.Status != string(entuser.StatusBanned) {
		t.Errorf("ban reply reports status %q, want %q", banned.Status, entuser.StatusBanned)
	}

	assertRefusedAsDisabled(t, "login after the ban", env.login(t, address, adminPassword))

	// Banning twice is a conflict rather than a silent success, so an operator
	// clicking twice is told the second click did nothing.
	second := env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/ban", nil)
	assertRefusedWith(t, "ban an already banned account", second, http.StatusConflict, codeConflict)
}

// TestAdminUnbanRestoresSignIn covers the reverse direction, which is what makes
// a ban an administrative decision rather than a permanent one.
func TestAdminUnbanRestoresSignIn(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "unban.target@example.com"
	userID := env.registerUser(t, address, "Unban Target")

	assertStatus(t, "ban", env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/ban", nil), http.StatusOK)
	assertRefusedAsDisabled(t, "login while banned", env.login(t, address, adminPassword))

	resp := env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/unban", nil)
	assertStatus(t, "unban", resp, http.StatusOK)

	var restored adminUserDTO
	resp.json(t, &restored)
	if restored.Status != string(entuser.StatusActive) {
		t.Errorf("unban reply reports status %q, want %q", restored.Status, entuser.StatusActive)
	}

	assertStatus(t, "login after the unban", env.login(t, address, adminPassword), http.StatusOK)
}

// TestAdminSuspendAndUnsuspend covers the reversible restriction on the same
// terms as the permanent one.
func TestAdminSuspendAndUnsuspend(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "suspend.target@example.com"
	userID := env.registerUser(t, address, "Suspend Target")

	assertStatus(t, "suspend",
		env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/suspend", nil), http.StatusOK)
	assertRefusedAsDisabled(t, "login while suspended", env.login(t, address, adminPassword))

	assertStatus(t, "unsuspend",
		env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/unsuspend", nil), http.StatusOK)
	assertStatus(t, "login after the unsuspend", env.login(t, address, adminPassword), http.StatusOK)
}

// TestAdminLiftingActionsRequireTheMatchingRestriction stops the two lifting
// endpoints from being general-purpose "make this account active" buttons.
//
// The recovery hold is the case that matters. It is the freeze applied after an
// account recovery, and it exists to keep an attacker out of an account they may
// have just taken over. An ordinary administrative action must not end it early,
// so both lifting endpoints refuse it and the restricting ones decline to
// overwrite it — otherwise ban-then-unban would launder the hold away.
func TestAdminLiftingActionsRequireTheMatchingRestriction(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "hold.target@example.com"
	userID := env.registerUser(t, address, "Hold Target")
	env.setStatus(t, address, entuser.StatusRecoveryHold)

	cases := []struct {
		action string
		want   string
	}{
		{action: "unban", want: codeConflict},
		{action: "unsuspend", want: codeConflict},
		// Restricting a frozen account is refused as well, so the hold cannot be
		// overwritten with a status that an administrator is allowed to lift.
		{action: "ban", want: codeConflict},
		{action: "suspend", want: codeConflict},
	}

	for _, tc := range cases {
		t.Run(tc.action+" is refused during a recovery hold", func(t *testing.T) {
			resp := env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/"+tc.action, nil)
			assertRefusedWith(t, tc.action, resp, http.StatusConflict, tc.want)
		})
	}

	// The hold has to still be in force, and still refusing sign-in, after all of
	// the above. This is the assertion the individual 409s are evidence for.
	ctx := env.bypassContext()
	after, err := env.client(ctx).User.Get(ctx, userID)
	if err != nil {
		t.Fatalf("re-reading held user: %v", err)
	}
	if after.Status != entuser.StatusRecoveryHold {
		t.Fatalf("status is %s after the refused actions, want the hold intact", after.Status)
	}
	assertRefusedAsDisabled(t, "login under the hold", env.login(t, address, adminPassword))

	// A lifting action against an account holding no restriction at all is the
	// same refusal, which is what keeps "unban" from meaning "activate".
	activeID := env.registerUser(t, "active.target@example.com", "Active Target")
	assertRefusedWith(t, "unban an active account",
		env.admin(t, http.MethodPost, "/v1/admin/users/"+activeID+"/unban", nil),
		http.StatusConflict, codeConflict)
}

// TestAdminRetireAndRestore covers the retirement lifecycle.
//
// A retired account answers a sign-in the way an unregistered address does. The
// row stays behind to keep the address reserved, so naming it would turn the
// login form into a way to ask which addresses were once registered.
func TestAdminRetireAndRestore(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "retire.target@example.com"
	userID := env.registerUser(t, address, "Retire Target")

	assertStatus(t, "retire",
		env.admin(t, http.MethodDelete, "/v1/admin/users/"+userID, nil), http.StatusOK)

	t.Run("sign-in reads as unknown rather than restricted", func(t *testing.T) {
		resp := env.login(t, address, adminPassword)
		if resp.status != http.StatusUnauthorized {
			t.Fatalf("login after retirement: got status %d, want 401; body %s", resp.status, resp.body)
		}
		var reply errorReply
		resp.json(t, &reply)
		if reply.Code == codeAccountDisabled {
			t.Errorf("retired account answered %q, disclosing that the address was registered", reply.Code)
		}
	})

	t.Run("the directory hides it by default and surfaces it on request", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users", nil)
		assertStatus(t, "default list", resp, http.StatusOK)
		var page adminUserListReply
		resp.json(t, &page)
		for _, listed := range emailsOf(page) {
			if strings.EqualFold(listed, address) {
				t.Fatalf("default listing included the retired account %s", address)
			}
		}

		// A console needs a restore queue, which is what deleted=true serves.
		resp = env.admin(t, http.MethodGet, "/v1/admin/users?deleted=true", nil)
		assertStatus(t, "deleted list", resp, http.StatusOK)
		resp.json(t, &page)

		var found bool
		for _, u := range page.Users {
			if strings.EqualFold(u.Email, address) {
				found = true
				if u.DeletedAt == nil {
					t.Error("retired account carried no deleted_at, so a console cannot offer a restore")
				}
			}
		}
		if !found {
			t.Fatalf("?deleted=true did not list the retired account %s", address)
		}
	})

	t.Run("retiring twice is a conflict", func(t *testing.T) {
		assertRefusedWith(t, "second retire",
			env.admin(t, http.MethodDelete, "/v1/admin/users/"+userID, nil),
			http.StatusConflict, codeConflict)
	})

	t.Run("restore brings the account back", func(t *testing.T) {
		resp := env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/restore", nil)
		assertStatus(t, "restore", resp, http.StatusOK)

		var back adminUserDTO
		resp.json(t, &back)
		if back.DeletedAt != nil {
			t.Errorf("restore reply still carries deleted_at = %v", *back.DeletedAt)
		}
		assertStatus(t, "login after the restore", env.login(t, address, adminPassword), http.StatusOK)
	})

	t.Run("restoring a live account is a conflict", func(t *testing.T) {
		assertRefusedWith(t, "restore a live account",
			env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/restore", nil),
			http.StatusConflict, codeConflict)
	})
}

// TestAdminRestoreDoesNotLaunderARestriction is the sharp edge of restore: it
// must return the account to the state it was retired in, not to active.
//
// Otherwise retire-then-restore would be an unban that the unban endpoint's own
// rules refuse to perform.
func TestAdminRestoreDoesNotLaunderARestriction(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "banned.retired@example.com"
	userID := env.registerUser(t, address, "Banned Then Retired")

	assertStatus(t, "ban", env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/ban", nil), http.StatusOK)
	assertStatus(t, "retire", env.admin(t, http.MethodDelete, "/v1/admin/users/"+userID, nil), http.StatusOK)

	resp := env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/restore", nil)
	assertStatus(t, "restore", resp, http.StatusOK)

	var back adminUserDTO
	resp.json(t, &back)
	if back.Status != string(entuser.StatusBanned) {
		t.Fatalf("restored account reports status %q, want it still %q",
			back.Status, entuser.StatusBanned)
	}

	assertRefusedAsDisabled(t, "login after restoring a banned account",
		env.login(t, address, adminPassword))
}

// TestAdminForceLogoutEndsEverySessionWithoutRestricting covers the response to a
// suspected token theft on an account that has done nothing wrong: every session
// ends, and the account itself stays usable.
func TestAdminForceLogoutEndsEverySessionWithoutRestricting(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "logout.target@example.com"
	userID := env.registerUser(t, address, "Logout Target")

	first := env.login(t, address, adminPassword)
	assertStatus(t, "first login", first, http.StatusOK)
	assertStatus(t, "second login", env.login(t, address, adminPassword), http.StatusOK)

	// Three, not two: signing up establishes a session of its own, so a new
	// account that then signs in twice is holding three. The count matters because
	// the endpoint reports what it revoked, and an operator reading that number
	// decides from it whether anything was live to cut off.
	const liveSessions = 3
	if live := env.liveSessionCount(t, address); live != liveSessions {
		t.Fatalf("live sessions before the forced sign-out = %d, want %d", live, liveSessions)
	}
	refreshCookie := first.cookie(refreshCookieName)
	if refreshCookie == nil {
		t.Fatalf("login did not set the %s cookie", refreshCookieName)
	}

	resp := env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/logout",
		map[string]string{"reason": "credential leaked in a support ticket"})
	assertStatus(t, "forced sign-out", resp, http.StatusOK)

	var reply adminLogoutReply
	resp.json(t, &reply)
	if reply.SessionsRevoked != liveSessions {
		t.Errorf("reported sessions_revoked = %d, want %d", reply.SessionsRevoked, liveSessions)
	}
	if reply.UserID != userID {
		t.Errorf("reply names user %q, want %q", reply.UserID, userID)
	}

	if live := env.liveSessionCount(t, address); live != 0 {
		t.Errorf("live sessions after the forced sign-out = %d, want 0", live)
	}

	// The cookie the client is still holding must no longer renew anything.
	assertRefusedWith(t, "refresh after the forced sign-out",
		env.do(t, http.MethodPost, "/v1/client/auth/refresh", nil, withCookie(refreshCookie)),
		http.StatusUnauthorized, codeSessionRevoked)

	// The account was not restricted, so signing in again has to work. This is what
	// separates a forced sign-out from a suspension.
	assertStatus(t, "login after the forced sign-out",
		env.login(t, address, adminPassword), http.StatusOK)
}

// TestAdminRevocationDoesNotArmAStaleTokenAgainstANewSession checks that a
// refresh token left over from a revoked session cannot take down the session its
// owner establishes afterwards.
//
// A client that was signed out by an administrator goes on holding the refresh
// token it had, and retries with it. That token names a revoked session, which
// looks like the reuse of a stolen secret — and the default reuse policy answers
// reuse by revoking every session the user has. If the two were not told apart, an
// ordinary retry from the user's own app would end the session they had just
// signed back in to, once per retry.
func TestAdminRevocationDoesNotArmAStaleTokenAgainstANewSession(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "stale.token@example.com"
	userID := env.registerUser(t, address, "Stale Token")

	signedIn := env.login(t, address, adminPassword)
	assertStatus(t, "login before the ban", signedIn, http.StatusOK)
	stale := signedIn.cookie(refreshCookieName)
	if stale == nil {
		t.Fatalf("login did not set the %s cookie", refreshCookieName)
	}

	assertStatus(t, "ban", env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/ban", nil), http.StatusOK)
	assertStatus(t, "unban", env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/unban", nil), http.StatusOK)

	reinstated := env.login(t, address, adminPassword)
	assertStatus(t, "login after the restriction was lifted", reinstated, http.StatusOK)
	live := reinstated.cookie(refreshCookieName)
	if live == nil {
		t.Fatalf("login after the lift did not set the %s cookie", refreshCookieName)
	}

	// The stale token is refused as revoked rather than as reuse: nothing was
	// exchanged for it, so there is no stolen successor to report.
	assertRefusedWith(t, "refresh with the token from before the ban",
		env.do(t, http.MethodPost, "/v1/client/auth/refresh", nil, withCookie(stale)),
		http.StatusUnauthorized, codeSessionRevoked)

	if count := env.liveSessionCount(t, address); count != 1 {
		t.Errorf("live sessions after the stale retry = %d, want the reinstated one to survive", count)
	}

	// The surviving session must still be usable, not merely present.
	assertStatus(t, "refresh with the reinstated session's own token",
		env.do(t, http.MethodPost, "/v1/client/auth/refresh", nil, withCookie(live)),
		http.StatusOK)
}

// TestAdminBanEndsEstablishedSessions checks a ban does not merely stop the next
// sign-in. An account banned while signed in must not be able to renew, or the
// restriction would only apply to somebody who had logged out first.
func TestAdminBanEndsEstablishedSessions(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "banned.session@example.com"
	userID := env.registerUser(t, address, "Banned Session")

	loginResp := env.login(t, address, adminPassword)
	assertStatus(t, "login", loginResp, http.StatusOK)
	refreshCookie := loginResp.cookie(refreshCookieName)
	if refreshCookie == nil {
		t.Fatalf("login did not set the %s cookie", refreshCookieName)
	}

	assertStatus(t, "ban", env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/ban", nil), http.StatusOK)

	if live := env.liveSessionCount(t, address); live != 0 {
		t.Errorf("live sessions after the ban = %d, want 0", live)
	}

	// Either refusal is correct here — the session was revoked and the account is
	// disabled — so the assertion is that renewal fails, not which of the two
	// reasons the handler reaches first.
	resp := env.do(t, http.MethodPost, "/v1/client/auth/refresh", nil, withCookie(refreshCookie))
	if resp.status == http.StatusOK {
		t.Fatalf("refresh renewed a banned account's session; body %s", resp.body)
	}
}

// TestAdminGetUserReportsTheSignInSurface covers the detail route, which exists
// so an operator can see what a restriction would cut off before applying it.
func TestAdminGetUserReportsTheSignInSurface(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "detail.target@example.com"
	userID := env.registerUser(t, address, "Detail Target")
	assertStatus(t, "login", env.login(t, address, adminPassword), http.StatusOK)

	resp := env.admin(t, http.MethodGet, "/v1/admin/users/"+userID, nil)
	assertStatus(t, "get", resp, http.StatusOK)

	var detail adminUserDetail
	resp.json(t, &detail)

	if detail.ID != userID {
		t.Errorf("detail names user %q, want %q", detail.ID, userID)
	}
	// Two sessions: the one signing up established, plus the one from the sign-in.
	if detail.ActiveSessions != 2 {
		t.Errorf("active_sessions = %d, want 2", detail.ActiveSessions)
	}
	if !detail.HasPassword {
		t.Error("has_password = false for an account that signed up with one")
	}
	// Both lists are always present so a client can tell "none enrolled" from a
	// field this version of the API did not send.
	if detail.SocialProviders == nil {
		t.Error("social_providers was null rather than an empty list")
	}
	if detail.TwoFactorTypes == nil {
		t.Error("two_factor_types was null rather than an empty list")
	}

	t.Run("an unknown ID is a 404", func(t *testing.T) {
		assertRefusedWith(t, "get an unknown user",
			env.admin(t, http.MethodGet, "/v1/admin/users/usr_does_not_exist", nil),
			http.StatusNotFound, codeNotFound)
	})
}

// TestAdminUserProjectionOmitsCredentials guards the field projection.
//
// The ORM row carries the password hash and the outstanding verification and
// magic-link tokens. Any of those in a directory listing would be a credential
// leak to every operator, and the tokens would be directly replayable, so the
// absence is asserted on the wire rather than trusted to the DTO definition.
func TestAdminUserProjectionOmitsCredentials(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "projection.target@example.com"
	userID := env.registerUser(t, address, "Projection Target")

	forbidden := []string{
		"password_hash",
		"email_verification_token",
		"email_verification_expires_at",
		"magic_link_token",
		"magic_link_expires_at",
		"recovery_codes",
		"password_reset_token",
		"totp_secret",
	}

	for _, route := range []string{"/v1/admin/users", "/v1/admin/users/" + userID} {
		resp := env.admin(t, http.MethodGet, route, nil)
		assertStatus(t, "get "+route, resp, http.StatusOK)

		body := string(resp.body)
		for _, field := range forbidden {
			if strings.Contains(body, field) {
				t.Errorf("%s exposed %q in its response body", route, field)
			}
		}
	}
}

// TestAdminListHonoursExplicitOrder covers the ordering contract.
//
// The ascending case is the one worth pinning: the direction and the sort key are
// separate parameters, and an implementation that derives one from the other
// answers ?order=asc with a descending page — a silent wrong answer rather than
// an error, which a console would render as a correct one.
func TestAdminListHonoursExplicitOrder(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	// Registration order is creation order, and Argon2id hashing puts a wide gap
	// between the rows, so created_at separates them unambiguously.
	ordered := []string{
		"first.created@example.com",
		"second.created@example.com",
		"third.created@example.com",
	}
	for _, address := range ordered {
		env.registerUser(t, address, "Ordered User")
	}

	newestFirst := []string{ordered[2], ordered[1], ordered[0]}

	cases := []struct {
		name  string
		query string
		want  []string
	}{
		{
			name:  "no parameters opens on newest first",
			query: "",
			want:  newestFirst,
		},
		{
			// The regression case. No sort key is named, so an implementation that
			// folds "no key" into "descend" ignores the direction that was asked for.
			name:  "ascending without a sort key is honoured",
			query: "?order=asc",
			want:  ordered,
		},
		{
			name:  "descending without a sort key",
			query: "?order=desc",
			want:  newestFirst,
		},
		{
			name:  "ascending with the sort key named explicitly",
			query: "?sort=created_at&order=asc",
			want:  ordered,
		},
		{
			name:  "email ascending",
			query: "?sort=email&order=asc",
			want:  []string{ordered[0], ordered[1], ordered[2]},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.admin(t, http.MethodGet, "/v1/admin/users"+tc.query, nil)
			assertStatus(t, "list"+tc.query, resp, http.StatusOK)

			var page adminUserListReply
			resp.json(t, &page)

			got := emailsOf(page)
			if len(got) != len(tc.want) {
				t.Fatalf("listed %d users, want %d: %v", len(got), len(tc.want), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("page order = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestAdminListPagesAndEchoesTheEffectiveWindow checks the page window, including
// the clamp being reported back. A caller that asked for more than the maximum
// pages on the number it is told, so the echo has to be the number that was used.
func TestAdminListPagesAndEchoesTheEffectiveWindow(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	for _, address := range []string{"page.one@example.com", "page.two@example.com", "page.three@example.com"} {
		env.registerUser(t, address, "Paged User")
	}

	t.Run("a window smaller than the total", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users?limit=2&offset=1", nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page adminUserListReply
		resp.json(t, &page)

		if len(page.Users) != 2 {
			t.Errorf("page holds %d users, want 2", len(page.Users))
		}
		// The total describes the filter, not the page, so a console can render a
		// page count from it.
		if page.Total != 3 {
			t.Errorf("total = %d, want 3", page.Total)
		}
		if page.Limit != 2 || page.Offset != 1 {
			t.Errorf("echoed window = limit %d offset %d, want 2/1", page.Limit, page.Offset)
		}
	})

	t.Run("a limit past the maximum is clamped and reported", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users?limit=10000", nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page adminUserListReply
		resp.json(t, &page)
		if page.Limit == 10000 {
			t.Fatal("an unbounded page size was accepted")
		}
		if page.Limit <= 0 {
			t.Fatalf("echoed limit = %d, want the clamped maximum", page.Limit)
		}
	})
}

// TestAdminListFiltersTheDirectory covers the filters an operator actually
// reaches for: find one address, and narrow by status.
func TestAdminListFiltersTheDirectory(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const bannedAddress = "filter.banned@example.com"
	const activeAddress = "filter.active@example.com"
	bannedID := env.registerUser(t, bannedAddress, "Filter Banned")
	env.registerUser(t, activeAddress, "Filter Active")
	assertStatus(t, "ban", env.admin(t, http.MethodPost, "/v1/admin/users/"+bannedID+"/ban", nil), http.StatusOK)

	t.Run("by exact email", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users?email="+activeAddress, nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page adminUserListReply
		resp.json(t, &page)
		if got := emailsOf(page); len(got) != 1 || got[0] != activeAddress {
			t.Fatalf("email filter returned %v, want just %s", got, activeAddress)
		}
	})

	t.Run("by status", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users?status=banned", nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page adminUserListReply
		resp.json(t, &page)
		if got := emailsOf(page); len(got) != 1 || got[0] != bannedAddress {
			t.Fatalf("status filter returned %v, want just %s", got, bannedAddress)
		}
	})

	t.Run("by search across name and address", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/users?q=filter.banned", nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page adminUserListReply
		resp.json(t, &page)
		if got := emailsOf(page); len(got) != 1 || got[0] != bannedAddress {
			t.Fatalf("search returned %v, want just %s", got, bannedAddress)
		}
	})
}

// TestAdminListRefusesUnusableFilters checks a filter that cannot be honoured is
// refused rather than dropped.
//
// This is the difference between an error and a wrong answer. Silently ignoring
// ?status=bannned answers a question the caller did not ask, and a console paging
// that result would report every account as unrestricted.
func TestAdminListRefusesUnusableFilters(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	cases := []struct {
		name  string
		query string
	}{
		{name: "misspelled status", query: "?status=bannned"},
		{name: "unknown sort key", query: "?sort=password_hash"},
		{name: "unknown order", query: "?order=sideways"},
		{name: "non-numeric limit", query: "?limit=lots"},
		{name: "zero limit", query: "?limit=0"},
		{name: "negative limit", query: "?limit=-5"},
		{name: "negative offset", query: "?offset=-1"},
		{name: "non-boolean flag", query: "?email_verified=maybe"},
		{name: "unparseable timestamp", query: "?created_after=yesterday"},
		{name: "inverted time window", query: "?created_after=2026-02-01T00:00:00Z&created_before=2026-01-01T00:00:00Z"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRefusedWith(t, "list"+tc.query,
				env.admin(t, http.MethodGet, "/v1/admin/users"+tc.query, nil),
				http.StatusBadRequest, codeValidationFailed)
		})
	}
}

// TestAdminUpdateProfile covers the profile patch: only named fields move, the
// metadata column merges rather than replaces, and a duplicate username is
// refused.
func TestAdminUpdateProfile(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "patch.target@example.com"
	userID := env.registerUser(t, address, "Patch Target")

	t.Run("only the named fields move", func(t *testing.T) {
		resp := env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID,
			map[string]any{"name": "Renamed Person"})
		assertStatus(t, "patch name", resp, http.StatusOK)

		var updated adminUserDTO
		resp.json(t, &updated)
		if updated.Name != "Renamed Person" {
			t.Errorf("name = %q, want %q", updated.Name, "Renamed Person")
		}
		if updated.Email != address {
			t.Errorf("email changed to %q on a patch that never named it", updated.Email)
		}
	})

	t.Run("metadata merges rather than replacing", func(t *testing.T) {
		resp := env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID,
			map[string]any{"metadata": map[string]any{"tier": "gold"}})
		assertStatus(t, "patch metadata", resp, http.StatusOK)

		resp = env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID,
			map[string]any{"metadata": map[string]any{"region": "eu"}})
		assertStatus(t, "patch second metadata key", resp, http.StatusOK)

		var updated adminUserDTO
		resp.json(t, &updated)
		if updated.Metadata["tier"] != "gold" {
			t.Errorf("the first metadata key was lost: %v", updated.Metadata)
		}
		if updated.Metadata["region"] != "eu" {
			t.Errorf("the second metadata key was not stored: %v", updated.Metadata)
		}
	})

	t.Run("an empty patch is refused", func(t *testing.T) {
		assertRefusedWith(t, "empty patch",
			env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID, map[string]any{}),
			http.StatusBadRequest, codeValidationFailed)
	})

	t.Run("a value failing validation is refused", func(t *testing.T) {
		assertRefusedWith(t, "avatar that is not a URL",
			env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID,
				map[string]any{"avatar_url": "javascript:alert(1)"}),
			http.StatusUnprocessableEntity, codeValidationFailed)
	})

	t.Run("a username already held is refused", func(t *testing.T) {
		assertStatus(t, "claim username",
			env.admin(t, http.MethodPatch, "/v1/admin/users/"+userID,
				map[string]any{"username": "taken_handle"}), http.StatusOK)

		otherID := env.registerUser(t, "patch.other@example.com", "Patch Other")
		assertRefusedWith(t, "duplicate username",
			env.admin(t, http.MethodPatch, "/v1/admin/users/"+otherID,
				map[string]any{"username": "taken_handle"}),
			http.StatusConflict, codeAlreadyExists)
	})

	t.Run("an unknown user is a 404", func(t *testing.T) {
		assertRefusedWith(t, "patch an unknown user",
			env.admin(t, http.MethodPatch, "/v1/admin/users/usr_does_not_exist",
				map[string]any{"name": "Nobody"}),
			http.StatusNotFound, codeNotFound)
	})
}

// TestAdminVerifyEmail covers the administrative override for the support case
// where the account holder cannot receive mail at their own address.
func TestAdminVerifyEmail(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "verify.target@example.com"
	userID := env.registerUser(t, address, "Verify Target")

	resp := env.admin(t, http.MethodGet, "/v1/admin/users/"+userID, nil)
	assertStatus(t, "get before verifying", resp, http.StatusOK)
	var before adminUserDetail
	resp.json(t, &before)
	if before.EmailVerified {
		t.Fatal("a freshly signed-up account already reported a verified address")
	}

	resp = env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/verify-email", nil)
	assertStatus(t, "verify", resp, http.StatusOK)

	var after adminUserDTO
	resp.json(t, &after)
	if !after.EmailVerified {
		t.Error("email_verified = false after an administrative verification")
	}

	// Verifying twice is a conflict, so an operator is told the second attempt
	// changed nothing.
	assertRefusedWith(t, "second verification",
		env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/verify-email", nil),
		http.StatusConflict, codeConflict)
}

// TestAdminActionsAreAudited checks each action leaves a record naming the key
// that performed it.
//
// The audit trail is the only place an administrative action is attributable
// after the fact. An endpoint that changes an account and writes nothing looks
// identical to one that was never called.
func TestAdminActionsAreAudited(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "audited.target@example.com"
	userID := env.registerUser(t, address, "Audited Target")

	assertStatus(t, "suspend",
		env.admin(t, http.MethodPost, "/v1/admin/users/"+userID+"/suspend",
			map[string]string{"reason": "chargeback under review"}), http.StatusOK)

	ctx := env.bypassContext()
	rows, err := env.client(ctx).AuditLog.Query().All(ctx)
	if err != nil {
		t.Fatalf("reading audit rows: %v", err)
	}

	var found bool
	for _, row := range rows {
		if row.EventType != "admin.user.suspended" {
			continue
		}
		found = true

		// The column is nullable, since a system event names no user, so an absent
		// target is a distinct failure from a wrong one.
		if row.UserID == nil {
			t.Error("audit row named no target user")
		} else if *row.UserID != userID {
			t.Errorf("audit row names user %q, want the target %q", *row.UserID, userID)
		}
		if row.TenantID != testTenant {
			t.Errorf("audit row landed in tenant %q, want %q", row.TenantID, testTenant)
		}
		// The secret key names no person, so the key ID is what makes the action
		// attributable at all.
		if row.APIKeyID == nil || *row.APIKeyID == "" {
			t.Error("audit row recorded no API key for a secret-key caller")
		}
		if reason, ok := row.Metadata["reason"].(string); !ok || reason != "chargeback under review" {
			t.Errorf("audit row metadata carried reason %v, want the operator's text", row.Metadata["reason"])
		}
		if method, ok := row.Metadata["admin_auth_method"].(string); !ok || method != "secret_key" {
			t.Errorf("audit row metadata carried admin_auth_method %v, want secret_key", row.Metadata["admin_auth_method"])
		}
	}
	if !found {
		t.Fatalf("no admin.user.suspended audit row was written; got %d rows", len(rows))
	}
}
