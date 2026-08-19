/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/service.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Orchestration for social OAuth2 sign-in — starting the provider
 *              round trip behind a single-use CSRF state, redeeming the
 *              callback into a linked, created or matched user, issuing the
 *              engine's own access token, and managing per-tenant provider
 *              credentials and their setup guidance.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/accountstatus"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/session"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

const (
	// defaultRefreshTokenTTL is the session lifetime used when configuration
	// leaves RefreshTokenTTL unset. It matches the auth service's own fallback so
	// both sign-in paths age out together.
	defaultRefreshTokenTTL = 720 * time.Hour

	// refreshTokenEntropyBytes is the randomness behind each refresh token, the
	// same width the password sign-in path uses.
	refreshTokenEntropyBytes = 32
)

var (
	// ErrProviderNotEnabled reports a provider configured but switched off.
	ErrProviderNotEnabled = errors.New("social provider not enabled for this tenant")
	// ErrProviderNotConfigured reports a provider with no credentials on file.
	ErrProviderNotConfigured = errors.New("social provider not configured for this tenant")
	// ErrEmailConflict reports an address already held by another account.
	ErrEmailConflict = errors.New("an account with this email already exists; sign in with your original method then link providers in account settings")
	// ErrEmailRequired reports a provider profile with no email address, which
	// leaves nothing to identify or create an account with.
	ErrEmailRequired = errors.New("provider did not return an email address; cannot create account")
	// ErrProviderAuthFailed reports a failed authentication at the provider.
	ErrProviderAuthFailed = errors.New("social provider authentication failed")
	// ErrRedirectNotAllowed reports a post-callback destination outside the
	// initiating application's registered redirect URIs.
	ErrRedirectNotAllowed = errors.New("post_callback_redirect is not an authorized redirect target for this application")
)

// providerFactory constructs the driver for a provider name. It matches
// NewProvider's signature.
type providerFactory func(name, clientID, clientSecret string, extraParam ...string) (IdentityProvider, error)

// Service orchestrates social sign-in on top of the repository and provider
// drivers.
type Service struct {
	// repo is the storage layer for state, identities and provider credentials.
	repo *Repository
	// sessions issues the session a completed sign-in is carried by. It is the
	// same store the password and passkey paths write to, so a social sign-in
	// appears in the user's session list and is reachable by revocation.
	sessions *session.Repository
	// cfg supplies the callback URL and the token signing key.
	cfg *config.Config
	// newProvider resolves a provider driver. It is a field rather than a direct
	// call to NewProvider because every network request this service makes goes
	// through the returned driver, and that is the one dependency a test cannot
	// supply for real.
	newProvider providerFactory
}

// NewService constructs a Service.
//
// sessions is required rather than optional: a sign-in that issues no session
// would produce an access token that cannot be refreshed, cannot be listed and
// cannot be revoked, which is indistinguishable from working until the first
// token expires.
func NewService(repo *Repository, cfg *config.Config, sessions *session.Repository) *Service {
	return &Service{repo: repo, cfg: cfg, sessions: sessions, newProvider: NewProvider}
}

// refreshTokenTTL is how long a session created here in environment may be
// refreshed before the user signs in again, matching the lifetime the password
// path uses and bounded by the same test-environment ceiling.
func (s *Service) refreshTokenTTL(environment string) time.Duration {
	if s.cfg == nil {
		return defaultRefreshTokenTTL
	}
	if s.cfg.RefreshTokenTTL > 0 {
		return s.cfg.RefreshTokenTTLFor(environment)
	}
	return s.cfg.ClampSessionTTL(environment, defaultRefreshTokenTTL)
}

// validatePostCallbackRedirect reports whether target is an authorized
// post-callback destination for the initiating application.
//
// The callback hands a live access token to this destination, so it is
// restricted to the application's registered exact_redirect_uris — the same
// allowlist the OAuth authorization endpoint checks redirect_uri against. The
// endpoint that accepts this parameter is authenticated by a publishable key,
// which is public by design; without this check anyone able to start a social
// login could name their own host and have the victim's browser deliver a token
// to it.
//
// A destination is authorized when it matches a registered URI exactly, or when
// it is same-origin — scheme, host and port all equal — with one. The origin
// relaxation lets an application registered for "https://app.example.com/callback"
// land the user on "https://app.example.com/dashboard"; it cannot move the token
// off the application's own origin, which is the property that matters. Matching
// on a prefix instead would authorize "https://app.example.com.evil.net".
//
// The check fails closed. An empty target is a no-op, but an unparseable URL, a
// non-http(s) scheme, a scheme-relative or path-relative URL, an absent
// application, or an empty allowlist all reject. Values like
// "javascript:alert(1)", "//evil.example.net/x" and "/dashboard" parse without
// error, so the absolute-http(s) test is explicit rather than implied by url.Parse.
//
// Returns ErrRedirectNotAllowed for an unauthorized destination, or a storage
// error if the application lookup itself fails.
func (s *Service) validatePostCallbackRedirect(
	ctx context.Context,
	tenantID, environment, applicationID, target string,
) error {
	if target == "" {
		return nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return ErrRedirectNotAllowed
	}

	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return ErrRedirectNotAllowed
	}

	if applicationID == "" {
		return ErrRedirectNotAllowed
	}

	client := s.repo.factory.GetClient(ctx, tenantID, environment)
	app, err := client.Application.Query().
		Where(application.ID(applicationID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrRedirectNotAllowed
		}
		return err
	}

	for _, raw := range app.ExactRedirectUris {
		if raw == target {
			return nil
		}
		registered, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if strings.EqualFold(registered.Scheme, scheme) && strings.EqualFold(registered.Host, u.Host) {
			return nil
		}
	}

	return ErrRedirectNotAllowed
}

// InitiateAuthorize starts a social sign-in and returns the provider
// authorization URL to redirect the browser to.
//
// The post-callback destination is validated before any other work, so an
// unauthorized one is refused without reading provider credentials or writing a
// state row.
//
// Returns ErrRedirectNotAllowed for an unauthorized destination,
// ErrProviderNotEnabled or ErrProviderNotConfigured when the provider is
// unusable, or a storage error.
func (s *Service) InitiateAuthorize(
	ctx context.Context,
	tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect string,
) (string, error) {
	if err := s.validatePostCallbackRedirect(ctx, tenantID, environment, applicationID, postCallbackRedirect); err != nil {
		return "", err
	}

	clientID, clientSecret, enabled, err := s.repo.GetDecryptedProviderConfig(ctx, tenantID, environment, provider)
	if err != nil {
		return "", err
	}
	if !enabled {
		return "", ErrProviderNotEnabled
	}
	if clientID == "" {
		return "", ErrProviderNotConfigured
	}

	p, err := s.newProvider(provider, clientID, clientSecret)
	if err != nil {
		return "", err
	}

	stateToken, err := s.repo.CreateSocialAuthState(ctx, tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect, s.cfg.SocialAuthStateTTL)
	if err != nil {
		return "", err
	}

	callbackURL := s.cfg.SocialCallbackURL(provider)
	authURL := p.AuthURL(stateToken, callbackURL)

	return authURL, nil
}

// CallbackResult is what a completed social sign-in produces.
type CallbackResult struct {
	// AccessToken is the engine's own short-lived bearer token. It carries the
	// session ID, which is what lets revocation and the token cutoff reach it.
	AccessToken string
	// RefreshToken is the raw refresh credential, returned only here because only
	// its digest is stored.
	RefreshToken string
	// SessionID identifies the session row both tokens belong to.
	SessionID string
	// PostCallbackRedirect is the authorized destination to send the browser to,
	// or empty when the caller should answer with the token in the response body.
	PostCallbackRedirect string
}

// HandleCallback completes a social sign-in and returns the tokens it issued
// together with the destination to send the browser to.
//
// The state is consumed first, which both authenticates the callback as one the
// engine started and prevents replay. The provider profile then resolves to an
// account three ways: an existing link signs that user in, a matching email
// links the provider to that account, and neither creates a new user.
//
// The sign-in is carried by a session row, exactly as the password and passkey
// paths are. That row is what makes the resulting access token refreshable,
// visible in the user's session list, and reachable by a revocation or a ban.
//
// The stored destination is re-validated here rather than trusted from the row,
// because this is the last point before a live token is handed to that host. An
// unauthorized destination degrades to an empty string, which makes the caller
// return the token in the response body instead of redirecting.
//
// ipAddress, userAgent and origin describe the request for the session row and
// the audit trail; all three may be empty.
//
// Returns ErrStateNotFound, ErrStateExpired, ErrEmailRequired, an account-status
// refusal, a provider error, or a storage error.
func (s *Service) HandleCallback(
	ctx context.Context,
	tenantID, provider, stateToken, code, ipAddress, userAgent, origin string,
) (*CallbackResult, error) {
	state, err := s.repo.ConsumeSocialAuthState(ctx, tenantID, stateToken)
	if err != nil {
		return nil, err
	}

	// The credentials come from the environment recorded on the state row, not
	// from the current request. The provider issued its code against whichever
	// OAuth application began the flow, and only that application's secret can
	// redeem it.
	clientID, clientSecret, _, err := s.repo.GetDecryptedProviderConfig(ctx, tenantID, state.Environment, provider)
	if err != nil {
		return nil, err
	}

	p, err := s.newProvider(provider, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// The redirect URI presented at the token endpoint must be identical to the
	// one used to obtain the code; providers reject a mismatch.
	callbackURL := s.cfg.SocialCallbackURL(provider)
	token, err := p.ExchangeCode(ctx, code, callbackURL)
	if err != nil {
		return nil, err
	}

	var providerUser *ProviderUser
	if provider == "apple" && token.IDToken != "" {
		// Apple has no userinfo endpoint; the profile arrives only in the
		// id_token returned by the exchange.
		providerUser, err = ParseAppleIDToken(token.IDToken)
	} else {
		providerUser, err = p.GetUserInfo(ctx, token.AccessToken)
	}
	if err != nil {
		return nil, err
	}

	if providerUser.Email == "" {
		return nil, ErrEmailRequired
	}

	var userID string
	var email string
	var name string
	var role string

	identity, err := s.repo.FindIdentityByProvider(ctx, provider, providerUser.ProviderUserID)
	if err != nil {
		return nil, err
	}

	if identity != nil {
		fetchedUser, err := s.getUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, err
		}
		if err := accountstatus.Allowed(fetchedUser); err != nil {
			return nil, err
		}
		userID = fetchedUser.ID
		email = fetchedUser.Email
		name = fetchedUser.Name
	} else {
		existingUser, err := s.repo.FindUserByEmailForSocial(ctx, state.TenantID, state.Environment, providerUser.Email)
		if err != nil {
			return nil, err
		}

		if existingUser != nil {
			// Proving control of the provider account does not lift a restriction on
			// the local account it maps to. Without this, a banned user could sign in
			// through Google even though the password path refuses them, and a
			// soft-deleted address would be linked to rather than left reserved.
			if err := accountstatus.Allowed(existingUser); err != nil {
				return nil, err
			}
			userID = existingUser.ID
			email = existingUser.Email
			name = existingUser.Name
		} else {
			newUser, err := s.repo.CreateSocialUser(ctx, state.TenantID, state.Environment, providerUser.Email, providerUser.Name, providerUser.AvatarURL, providerUser.EmailVerified)
			if err != nil {
				return nil, err
			}
			userID = newUser.ID
			email = newUser.Email
			name = newUser.Name
		}
	}

	// The role claim is resolved from recorded roles rather than fixed: a social
	// sign-in may be a tenant admin returning through Google or GitHub, and a
	// blank role would strip that privilege. A new user has no roles and
	// resolves to empty naturally.
	role = rbac.ResolveConsoleRoleClaim(ctx, s.repo.factory.GetClient(ctx, "", ""), userID)

	// The refresh token is generated here rather than left to the session store's
	// fallback, so that the credential this path mints is the same shape and
	// strength as the one the password path mints.
	tokenBytes := make([]byte, refreshTokenEntropyBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed generating refresh token: %w", err)
	}

	sess, rawRefreshToken, err := s.sessions.CreateSession(
		ctx,
		state.TenantID,
		state.Environment,
		userID,
		hex.EncodeToString(tokenBytes),
		ipAddress,
		userAgent,
		"",
		"",
		s.refreshTokenTTL(state.Environment),
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating session for social sign-in: %w", err)
	}

	jwtToken, err := jwtpkg.IssueAccessTokenWithSession(userID, state.TenantID, state.Environment, email, name, role, sess.ID, s.cfg.EncryptionKey, s.cfg.AccessTokenTTLFor(state.Environment))
	if err != nil {
		return nil, fmt.Errorf("failed issuing access token: %w", err)
	}

	_, err = s.repo.UpsertIdentity(ctx, userID, provider, providerUser.ProviderUserID, providerUser.Email, providerUser.Name, providerUser.AvatarURL, providerUser.RawProfile, token.AccessToken, token.RefreshToken)
	if err != nil {
		return nil, err
	}

	// Sign-in bookkeeping. The tokens above are already valid, so a failure here
	// is logged and stepped over: refusing the sign-in would cost the user their
	// session to save a timestamp, and the session row itself already records that
	// the sign-in happened.
	if err := s.repo.UpdateUserLastSignIn(ctx, userID); err != nil {
		log.Printf("[SOCIAL] last sign-in stamp failed for user %s: %v", userID, err)
	}
	if err := s.repo.CreateSignInAuditLog(ctx, state.TenantID, state.ApplicationID, userID, provider, ipAddress, userAgent, origin); err != nil {
		log.Printf("[SOCIAL] sign-in audit log failed for user %s: %v", userID, err)
	}

	postCallback := state.PostCallbackRedirect
	if err := s.validatePostCallbackRedirect(ctx, state.TenantID, state.Environment, state.ApplicationID, postCallback); err != nil {
		if !errors.Is(err, ErrRedirectNotAllowed) {
			return nil, err
		}
		postCallback = ""
	}

	return &CallbackResult{
		AccessToken:          jwtToken,
		RefreshToken:         rawRefreshToken,
		SessionID:            sess.ID,
		PostCallbackRedirect: postCallback,
	}, nil
}

// ProviderSetupResponse describes a provider's configuration state and the
// steps needed to finish setting it up.
type ProviderSetupResponse struct {
	// Provider is the canonical provider name.
	Provider string `json:"provider"`
	// Enabled reports whether the tenant has switched the provider on.
	Enabled bool `json:"enabled"`
	// ClientID is the configured public client identifier. The client secret is
	// never included.
	ClientID string `json:"client_id"`
	// Configured reports whether credentials are present.
	Configured bool `json:"configured"`
	// Setup carries the console URL, callback URL and instructions.
	Setup ProviderSetup `json:"setup"`
}

// GetSetupGuide returns setup guidance and current configuration for one
// provider, or for every supported provider when provider is empty.
//
// Providers with no configuration are still described, so an administrator can
// see what is available rather than only what is already set up. Secrets are
// never included.
//
// environment selects which set of credentials is reported, so the settings
// screen shows the test client ID to a test key and the live one to a live key.
//
// Returns a storage error if the tenant's configuration cannot be read.
func (s *Service) GetSetupGuide(ctx context.Context, tenantID, environment, provider string) ([]ProviderSetupResponse, error) {
	configs, err := s.repo.GetAllProviderConfigs(ctx, tenantID, environment)
	if err != nil {
		return nil, err
	}

	var res []ProviderSetupResponse
	supported := SupportedProviders()
	if provider != "" {
		supported = []string{provider}
	}

	for _, pName := range supported {
		// Setup instructions are static per provider, so placeholder credentials
		// are enough to construct a driver and ask for them.
		p, err := s.newProvider(pName, "x", "x")
		if err != nil {
			continue
		}

		callbackURL := s.cfg.SocialCallbackURL(pName)
		setup := p.SetupInstructions(callbackURL)

		conf, ok := configs[pName]
		if !ok {
			conf = &ProviderConfig{}
		}

		res = append(res, ProviderSetupResponse{
			Provider:   pName,
			Enabled:    conf.Enabled,
			ClientID:   conf.ClientID,
			Configured: conf.ClientID != "",
			Setup:      setup,
		})
	}
	return res, nil
}

// ConfigureProvider validates and stores a provider's credentials for one
// environment.
//
// The format check runs only when a secret is supplied, because an empty secret
// means "keep the stored one" rather than "clear it".
//
// The write is confined to environment, so a tenant can point its test sign-in
// page at a throwaway OAuth application while its live one keeps the credentials
// its real users depend on.
//
// Returns *ErrInvalidClientCredentials for a malformed credential, or a storage
// error.
func (s *Service) ConfigureProvider(
	ctx context.Context,
	tenantID, environment, provider string,
	enabled bool,
	clientID, clientSecret string,
) error {
	if clientSecret != "" {
		if err := ValidateClientCredentials(provider, clientID, clientSecret); err != nil {
			return err
		}
	}
	return s.repo.SetProviderConfig(ctx, tenantID, environment, provider, enabled, clientID, clientSecret)
}

// RemoveProvider deletes a provider's configuration from one of the tenant's
// environments, leaving the other untouched.
//
// Returns a storage error if the write fails.
func (s *Service) RemoveProvider(ctx context.Context, tenantID, environment, provider string) error {
	return s.repo.DeleteProviderConfig(ctx, tenantID, environment, provider)
}

// getUserByID loads a user by ID, returning an error if no such user exists.
func (s *Service) getUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}
