//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/session_activity_writer_test.go
 * Tier: Integration Test
 *
 * Covers the writers of per-application session activity: signing in records the
 * pairing, and refreshing carries it onto the successor session instead of
 * starting a new one.
 *
 * The carry-forward is what keeps the table bounded. A refresh rotates the
 * session — a new row, the old one parked in its grace window — and nothing in
 * the engine reaps retired sessions, so activity that stayed keyed on the
 * outgoing session would accumulate a row per application per rotation, each
 * with a first_seen_at that had forgotten when the login actually began.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	entsession "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sessionappactivity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sessionactivity"
)

// sessionForToken resolves the session a raw refresh token belongs to.
//
// Only the digest is stored, so the lookup hashes the token the same way the
// engine does rather than matching it directly.
func (e *testEnv) sessionForToken(t *testing.T, rawToken string) *ent.Session {
	t.Helper()
	ctx := e.bypassContext()
	sess, err := e.client(ctx).Session.Query().
		Where(entsession.RefreshTokenHash(session.HashRefreshToken(rawToken))).
		Only(ctx)
	if err != nil {
		t.Fatalf("resolving the session behind a refresh token: %v", err)
	}
	return sess
}

// activityFor returns the activity rows recorded against one session, oldest
// pairing first.
func (e *testEnv) activityFor(t *testing.T, sessionID string) []*ent.SessionAppActivity {
	t.Helper()
	ctx := e.bypassContext()
	rows, err := e.client(ctx).SessionAppActivity.Query().
		Where(sessionappactivity.SessionID(sessionID)).
		Order(ent.Asc(sessionappactivity.FieldFirstSeenAt), ent.Asc(sessionappactivity.FieldID)).
		All(ctx)
	if err != nil {
		t.Fatalf("reading activity for session %s: %v", sessionID, err)
	}
	return rows
}

// seedActivityAt records a pairing with explicit timestamps.
//
// first_seen_at is immutable, so a test that needs a pairing which began long
// ago has to say so at creation; there is no later adjustment.
func (e *testEnv) seedActivityAt(t *testing.T, activityID, sessionID, appID string, firstSeen, lastActive time.Time) {
	t.Helper()
	ctx := e.bypassContext()
	if _, err := e.client(ctx).SessionAppActivity.Create().
		SetID(activityID).
		SetSessionID(sessionID).
		SetApplicationID(appID).
		SetFirstSeenAt(firstSeen).
		SetLastActiveAt(lastActive).
		Save(ctx); err != nil {
		t.Fatalf("seeding activity %s: %v", activityID, err)
	}
}

// backdateActivity rewrites a row's last-active time.
//
// Tests that want to observe the stamp advancing move it into the past first,
// so the assertion compares against a distant instant rather than against
// whatever resolution the storage layer keeps for two writes a millisecond
// apart.
func (e *testEnv) backdateActivity(t *testing.T, activityID string, when time.Time) {
	t.Helper()
	ctx := e.bypassContext()
	if err := e.client(ctx).SessionAppActivity.UpdateOneID(activityID).
		SetLastActiveAt(when).
		Exec(ctx); err != nil {
		t.Fatalf("backdating activity %s: %v", activityID, err)
	}
}

// TestLoginRecordsActivityAtTheRequestApplication checks that signing in pairs
// the new session with the application the request authenticated as.
//
// The application is never passed to the session writer; it is read from the
// privacy context the publishable-key middleware installs. So this also covers
// that plumbing: a broken context yields a session with no activity at all
// rather than a visible error.
func TestLoginRecordsActivityAtTheRequestApplication(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "activity_login@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "Activity Login"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}
	cookie := loginResp.cookie(refreshCookieName)
	if cookie == nil {
		t.Fatalf("login did not set the %s cookie", refreshCookieName)
	}

	sess := env.sessionForToken(t, cookie.Value)
	rows := env.activityFor(t, sess.ID)
	if len(rows) != 1 {
		t.Fatalf("activity rows for the session just signed in: got %d, want 1", len(rows))
	}
	if rows[0].ApplicationID != testApplication {
		t.Errorf("activity recorded against application %q, want %q — the pairing names the wrong app",
			rows[0].ApplicationID, testApplication)
	}
	if !rows[0].FirstSeenAt.Equal(rows[0].LastActiveAt) {
		t.Errorf("first use recorded first_seen_at %s and last_active_at %s; a pairing's first use is also its latest",
			rows[0].FirstSeenAt, rows[0].LastActiveAt)
	}
}

// TestRefreshCarriesActivityToTheSuccessorSession drives a refresh through the
// OAuth token endpoint and checks the pairing moved rather than multiplied.
//
// The row identity is the assertion that matters: a carried-forward pairing is
// the same row re-pointed, so its ID survives, while a pairing recreated
// against the successor would carry a fresh ID and a first_seen_at reset to the
// moment of the refresh.
func TestRefreshCarriesActivityToTheSuccessorSession(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const address = "activity_refresh@example.com"
	const password = "SuperSecret123!"

	if resp := env.signUp(t, address, password, "Activity Refresh"); resp.status != http.StatusCreated {
		t.Fatalf("signup: got status %d, want 201; body %s", resp.status, resp.body)
	}

	loginResp := env.login(t, address, password)
	if loginResp.status != http.StatusOK {
		t.Fatalf("login: got status %d, want 200; body %s", loginResp.status, loginResp.body)
	}
	initial := loginResp.cookie(refreshCookieName)
	if initial == nil {
		t.Fatalf("login did not set the %s cookie", refreshCookieName)
	}

	oldSession := env.sessionForToken(t, initial.Value)
	before := env.activityFor(t, oldSession.ID)
	if len(before) != 1 {
		t.Fatalf("activity rows after login: got %d, want 1", len(before))
	}
	stale := time.Now().Add(-time.Hour)
	env.backdateActivity(t, before[0].ID, stale)

	rotateResp := env.do(t, http.MethodPost, "/v1/oauth/token",
		refreshRequest{GrantType: "refresh_token"}, withCookie(initial))
	if rotateResp.status != http.StatusOK {
		t.Fatalf("refresh: got status %d, want 200; body %s", rotateResp.status, rotateResp.body)
	}
	rotated := rotateResp.cookie(refreshCookieName)
	if rotated == nil {
		t.Fatalf("refresh did not set a replacement %s cookie", refreshCookieName)
	}
	newSession := env.sessionForToken(t, rotated.Value)

	if left := env.activityFor(t, oldSession.ID); len(left) != 0 {
		t.Errorf("activity rows left on the rotated-out session: got %d, want 0; "+
			"rows keyed on retired sessions accumulate one per application per refresh", len(left))
	}

	after := env.activityFor(t, newSession.ID)
	if len(after) != 1 {
		t.Fatalf("activity rows on the successor session: got %d, want 1", len(after))
	}
	if after[0].ID != before[0].ID {
		t.Errorf("activity row ID changed from %s to %s: the pairing was recreated rather than carried forward, "+
			"so first_seen_at no longer says when this login reached the application",
			before[0].ID, after[0].ID)
	}
	if !after[0].FirstSeenAt.Equal(before[0].FirstSeenAt) {
		t.Errorf("first_seen_at moved from %s to %s across a refresh",
			before[0].FirstSeenAt, after[0].FirstSeenAt)
	}
	if !after[0].LastActiveAt.After(stale) {
		t.Errorf("last_active_at is %s, still at or behind the backdated %s: the refresh was not recorded",
			after[0].LastActiveAt, stale)
	}
}

// TestCarryForwardMovesEveryApplicationAndMergesTheOverlap covers the shape a
// multi-application tenant produces: one session used at two applications, one
// of which the successor has already recorded for itself.
//
// The overlap is not an error to be tolerated but a case with a defined answer.
// Two rows describing one pairing collapse to one, keeping the older
// first_seen_at — the login's real beginning — and the newer last_active_at.
// Which of the two writes lands first depends on the rotation path taken, so
// the merge is what makes the result the same either way.
func TestCarryForwardMovesEveryApplicationAndMergesTheOverlap(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const secondApp = "app_00000000000000000000000000000003"
	if err := env.authRepo.EnsureDefaultApplicationExists(env.bypassContext(),
		secondApp, testTenant, []string{"http://localhost:3000/third"}); err != nil {
		t.Fatalf("seeding second application: %v", err)
	}

	env.seedUser(t, testTenant, "usr_carry", "carry@activity.example")
	env.seedSession(t, "ses_carry_old", "usr_carry")
	env.seedSession(t, "ses_carry_new", "usr_carry")
	began := time.Now().Add(-2 * time.Hour)
	env.seedActivityAt(t, "saa_carry_primary", "ses_carry_old", testApplication, began, began)
	env.seedActivityAt(t, "saa_carry_secondary", "ses_carry_old", secondApp, began, began)

	// Read the pairings back before touching anything, so the comparison after
	// the merge is against the timestamps the database holds rather than the ones
	// handed to it.
	seeded := env.activityFor(t, "ses_carry_old")
	if len(seeded) != 2 {
		t.Fatalf("seeded activity rows: got %d, want 2", len(seeded))
	}
	var seededPrimary *ent.SessionAppActivity
	for _, row := range seeded {
		if row.ID == "saa_carry_primary" {
			seededPrimary = row
		}
	}
	if seededPrimary == nil {
		t.Fatal("seeded pairing saa_carry_primary is missing")
	}

	// The successor records its own use before the move runs, which is the order
	// the OAuth refresh path produces: the session is created — and stamped — and
	// only then is the outgoing one retired.
	scoped := privacy.NewContext(env.bypassContext(), testTenant, testApplication, testEnvironment)
	if err := sessionactivity.Touch(scoped, env.client(scoped), "ses_carry_new"); err != nil {
		t.Fatalf("recording the successor's own use: %v", err)
	}
	if err := sessionactivity.CarryForward(scoped, env.client(scoped), "ses_carry_old", "ses_carry_new"); err != nil {
		t.Fatalf("carrying activity forward: %v", err)
	}

	if left := env.activityFor(t, "ses_carry_old"); len(left) != 0 {
		t.Errorf("activity rows left on the outgoing session: got %d, want 0", len(left))
	}

	rows := env.activityFor(t, "ses_carry_new")
	if len(rows) != 2 {
		t.Fatalf("activity rows on the successor: got %d, want 2 (one per application the session reached)", len(rows))
	}

	byApp := map[string]*ent.SessionAppActivity{}
	for _, row := range rows {
		byApp[row.ApplicationID] = row
	}

	overlapping, ok := byApp[testApplication]
	if !ok {
		t.Fatalf("no activity for %s on the successor; applications present: %v", testApplication, byApp)
	}
	if overlapping.ID != "saa_carry_primary" {
		t.Errorf("the overlapping pairing survived as row %s, want saa_carry_primary: "+
			"the merge kept the successor's newer row and lost the login's first_seen_at", overlapping.ID)
	}
	if !overlapping.FirstSeenAt.Equal(seededPrimary.FirstSeenAt) {
		t.Errorf("merged first_seen_at is %s, want the older %s", overlapping.FirstSeenAt, seededPrimary.FirstSeenAt)
	}
	if !overlapping.LastActiveAt.After(seededPrimary.LastActiveAt) {
		t.Errorf("merged last_active_at is %s, want the newer stamp from the successor's own use", overlapping.LastActiveAt)
	}

	carried, ok := byApp[secondApp]
	if !ok {
		t.Fatalf("activity at %s was dropped instead of moved; applications present: %v", secondApp, byApp)
	}
	if carried.ID != "saa_carry_secondary" {
		t.Errorf("the non-overlapping pairing survived as row %s, want saa_carry_secondary", carried.ID)
	}
}
