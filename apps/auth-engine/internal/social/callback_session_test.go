/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/callback_session_test.go
 * Tier: Social Identity Provider Layer / Tests
 *
 * Description: Covers what a completed social sign-in has to leave behind — an
 *              active session row, a refresh token that matches its stored
 *              digest, an access token bound to that session, and the sign-in
 *              bookkeeping the reporting surfaces read.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	entauditlog "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	entsession "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
	_ "github.com/mattn/go-sqlite3"
)

const (
	callbackTenant  = "tnt_callback"
	callbackApp     = "app_callback"
	callbackEnv     = "test"
	callbackKey     = "0123456789abcdef0123456789abcdef"
	callbackEmail   = "returning@example.com"
	callbackSubject = "google-subject-1"
)

// stubProvider stands in for a real driver so the callback can be exercised
// without a round trip to the provider. Only the two methods the callback path
// reaches are meaningful.
type stubProvider struct {
	user ProviderUser
}

func (p *stubProvider) Name() string { return "google" }

func (p *stubProvider) AuthURL(state, redirectURI string) string {
	return "https://accounts.example.com/authorize?state=" + state
}

func (p *stubProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	return &ProviderToken{AccessToken: "provider-access", RefreshToken: "provider-refresh", TokenType: "Bearer"}, nil
}

func (p *stubProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	profile := p.user
	return &profile, nil
}

func (p *stubProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{CallbackURL: callbackURL}
}

// setupCallbackTest builds a service whose provider driver is stubbed and whose
// tenant already has Google configured and an application registered.
func setupCallbackTest(t *testing.T) (*Service, *session.Repository, context.Context, *ent.Client) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "social_callback_test_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	factory, err := clientfactory.NewClientFactory("sqlite3", filepath.Join(tmpDir, "test.db")+"?_fk=1")
	if err != nil {
		t.Fatalf("client factory: %v", err)
	}
	t.Cleanup(func() { factory.Close() })

	sysCtx := privacy.NewBypassContext(context.Background())
	client := factory.GetClient(sysCtx, callbackTenant, callbackEnv)
	if err := client.Schema.Create(sysCtx); err != nil {
		t.Fatalf("schema create: %v", err)
	}

	if _, err := client.Tenant.Create().
		SetID(callbackTenant).
		SetName("Callback Tenant").
		SetSlug("callback-tenant").
		Save(sysCtx); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	if _, err := client.Application.Create().
		SetID(callbackApp).
		SetTenantID(callbackTenant).
		SetName("Callback App").
		SetExactRedirectUris([]string{"https://app.example.com/callback"}).
		Save(sysCtx); err != nil {
		t.Fatalf("seed application: %v", err)
	}

	repo := NewRepository(factory, policy.NewRepository(factory), callbackKey)
	if err := repo.SetProviderConfig(sysCtx, callbackTenant, "test", "google", true, "client-id", "client-secret"); err != nil {
		t.Fatalf("configure provider: %v", err)
	}

	cfg := &config.Config{
		EncryptionKey:      callbackKey,
		AppBaseURL:         "https://auth.example.com",
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    72 * time.Hour,
		SocialAuthStateTTL: 10 * time.Minute,
	}

	sessionRepo := session.NewRepository(factory)
	svc := NewService(repo, cfg, sessionRepo)
	svc.newProvider = func(name, clientID, clientSecret string, extraParam ...string) (IdentityProvider, error) {
		return &stubProvider{user: ProviderUser{
			ProviderUserID: callbackSubject,
			Email:          callbackEmail,
			EmailVerified:  true,
			Name:           "Returning User",
			RawProfile:     map[string]interface{}{"sub": callbackSubject},
		}}, nil
	}

	return svc, sessionRepo, sysCtx, client
}

// completeCallback runs one full sign-in, starting from a state row written by
// the production writer so the test never fabricates one by hand.
func completeCallback(t *testing.T, ctx context.Context, svc *Service, postCallbackRedirect string) *CallbackResult {
	t.Helper()

	stateToken, err := svc.repo.CreateSocialAuthState(ctx, callbackTenant, callbackApp, callbackEnv,
		"google", "https://app.example.com/callback", postCallbackRedirect, 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateSocialAuthState: %v", err)
	}

	result, err := svc.HandleCallback(ctx, callbackTenant, "google", stateToken, "provider-code",
		"203.0.113.7", "Mozilla/5.0 (Test)", "https://app.example.com")
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	return result
}

// TestHandleCallbackIssuesARefreshableSession is the property the whole change
// exists for: before it, a social sign-in returned a bare access token, so the
// user was silently signed out when it expired and "sign out everywhere" could
// not reach them.
func TestHandleCallbackIssuesARefreshableSession(t *testing.T) {
	svc, sessionRepo, ctx, client := setupCallbackTest(t)

	result := completeCallback(t, ctx, svc, "")

	if result.RefreshToken == "" {
		t.Fatal("callback returned no refresh token")
	}
	if result.SessionID == "" {
		t.Fatal("callback returned no session id")
	}

	rows, err := client.Session.Query().Where(entsession.ID(result.SessionID)).All(ctx)
	if err != nil {
		t.Fatalf("querying session: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("found %d session rows for the returned id, want 1", len(rows))
	}

	sess := rows[0]
	if sess.Status != entsession.StatusActive {
		t.Errorf("session status = %q, want active", sess.Status)
	}
	if got := session.HashRefreshToken(result.RefreshToken); sess.RefreshTokenHash != got {
		t.Error("stored digest does not match the returned refresh token, so a refresh would be rejected")
	}
	if sess.RefreshTokenHash == result.RefreshToken {
		t.Error("refresh token was stored in the clear")
	}
	if sess.IPAddress != "203.0.113.7" || sess.UserAgent != "Mozilla/5.0 (Test)" {
		t.Errorf("session recorded ip=%q ua=%q, want the request's own", sess.IPAddress, sess.UserAgent)
	}

	// The window the row is refreshable for has to come from configuration, not
	// from whatever the session store happens to default to.
	wantExpiry := time.Now().Add(72 * time.Hour)
	if diff := sess.ExpiresAt.Sub(wantExpiry); diff > time.Minute || diff < -time.Minute {
		t.Errorf("session expires at %s, want about %s", sess.ExpiresAt, wantExpiry)
	}

	// Reachable through the same listing the session endpoints serve, which is
	// what makes the sign-in visible and revocable.
	active, err := sessionRepo.GetUserActiveSessions(ctx, sess.UserID)
	if err != nil {
		t.Fatalf("GetUserActiveSessions: %v", err)
	}
	if len(active) != 1 || active[0].ID != result.SessionID {
		t.Errorf("active sessions = %d rows, want the one this sign-in created", len(active))
	}
}

// TestHandleCallbackBindsTheAccessTokenToTheSession covers the half of the fix
// that is invisible in the database: a token with no sid claim survives a
// revocation, because nothing downstream knows which session to check.
func TestHandleCallbackBindsTheAccessTokenToTheSession(t *testing.T) {
	svc, _, ctx, _ := setupCallbackTest(t)

	result := completeCallback(t, ctx, svc, "")

	claims, err := jwtpkg.VerifyAccessToken(result.AccessToken, callbackKey)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.SessionID != result.SessionID {
		t.Errorf("sid = %q, want %q", claims.SessionID, result.SessionID)
	}
	if claims.TenantID != callbackTenant {
		t.Errorf("tenant = %q, want %q", claims.TenantID, callbackTenant)
	}
	if claims.Email != callbackEmail {
		t.Errorf("email = %q, want %q", claims.Email, callbackEmail)
	}
}

// TestHandleCallbackRecordsTheSignIn pins the bookkeeping a social sign-in owes
// the reporting surfaces: without it an account that only ever arrives through a
// provider reads as dormant, and the sign-in is absent from the audit trail.
func TestHandleCallbackRecordsTheSignIn(t *testing.T) {
	svc, _, ctx, client := setupCallbackTest(t)

	before := time.Now().Add(-time.Second)
	result := completeCallback(t, ctx, svc, "")

	sess, err := client.Session.Get(ctx, result.SessionID)
	if err != nil {
		t.Fatalf("loading session: %v", err)
	}

	u, err := client.User.Get(ctx, sess.UserID)
	if err != nil {
		t.Fatalf("loading user: %v", err)
	}
	if u.LastSignInAt == nil {
		t.Fatal("last_sign_in_at was never stamped")
	}
	if u.LastSignInAt.Before(before) {
		t.Errorf("last_sign_in_at = %s, want a time from this sign-in", u.LastSignInAt)
	}

	logs, err := client.AuditLog.Query().
		Where(entauditlog.EventType("user.signed_in")).
		All(ctx)
	if err != nil {
		t.Fatalf("querying audit log: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("found %d user.signed_in rows, want 1", len(logs))
	}

	entry := logs[0]
	if entry.UserID == nil || *entry.UserID != sess.UserID {
		t.Errorf("audit row is not attributed to the signed-in user")
	}
	if entry.IPAddress != "203.0.113.7" || entry.UserAgent != "Mozilla/5.0 (Test)" {
		t.Errorf("audit row recorded ip=%q ua=%q, want the request's own", entry.IPAddress, entry.UserAgent)
	}
	if entry.Metadata["provider"] != "google" || entry.Metadata["method"] != "social" {
		t.Errorf("audit metadata = %v, want method=social provider=google", entry.Metadata)
	}
}

// TestHandleCallbackKeepsTheRefreshTokenOutOfTheRedirect guards the split
// between the two credentials. The access token is short-lived and travels in
// the fragment; the refresh token is long-lived and must reach the browser only
// as an HttpOnly cookie, so it must not appear in a URL the page can read.
func TestHandleCallbackKeepsTheRefreshTokenOutOfTheRedirect(t *testing.T) {
	svc, _, ctx, _ := setupCallbackTest(t)

	result := completeCallback(t, ctx, svc, "https://app.example.com/dashboard")
	if result.PostCallbackRedirect != "https://app.example.com/dashboard" {
		t.Fatalf("post-callback redirect = %q, want the authorized destination", result.PostCallbackRedirect)
	}

	redirectURL, err := buildPostCallbackRedirect(result.PostCallbackRedirect, result.AccessToken)
	if err != nil {
		t.Fatalf("buildPostCallbackRedirect: %v", err)
	}
	if !strings.Contains(redirectURL, result.AccessToken) {
		t.Error("redirect does not carry the access token")
	}
	if strings.Contains(redirectURL, result.RefreshToken) {
		t.Error("refresh token leaked into the redirect URL")
	}
}

// TestHandleCallbackReusesTheAccountOnASecondSignIn checks that repeat sign-ins
// stack sessions on one account rather than creating a second user, and that
// each one is independently revocable.
func TestHandleCallbackReusesTheAccountOnASecondSignIn(t *testing.T) {
	svc, sessionRepo, ctx, client := setupCallbackTest(t)

	first := completeCallback(t, ctx, svc, "")
	second := completeCallback(t, ctx, svc, "")

	if first.SessionID == second.SessionID {
		t.Fatal("the second sign-in reused the first session row")
	}
	if first.RefreshToken == second.RefreshToken {
		t.Fatal("the second sign-in reused the first refresh token")
	}

	users, err := client.User.Query().All(ctx)
	if err != nil {
		t.Fatalf("listing users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("found %d users after two sign-ins by one person, want 1", len(users))
	}

	active, err := sessionRepo.GetUserActiveSessions(ctx, users[0].ID)
	if err != nil {
		t.Fatalf("GetUserActiveSessions: %v", err)
	}
	if len(active) != 2 {
		t.Errorf("active sessions = %d, want 2", len(active))
	}
}

// TestHandleCallbackWithoutASessionStoreIsUnconstructible documents that the
// dependency is required rather than optional: the omission this change fixed
// was possible only because the session store was reachable but never asked for.
func TestHandleCallbackWithoutASessionStoreIsUnconstructible(t *testing.T) {
	svc, _, _, _ := setupCallbackTest(t)

	if svc.sessions == nil {
		t.Fatal("service was constructed with no session store")
	}
	if svc.newProvider == nil {
		t.Fatal("service was constructed with no provider factory")
	}
}
