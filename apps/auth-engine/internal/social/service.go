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
	"errors"
	"net/url"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/application"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/rbac"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
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

// Service orchestrates social sign-in on top of the repository and provider
// drivers.
type Service struct {
	// repo is the storage layer for state, identities and provider credentials.
	repo *Repository
	// cfg supplies the callback URL and the token signing key.
	cfg *config.Config
}

// NewService constructs a Service.
func NewService(repo *Repository, cfg *config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
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

	clientID, clientSecret, enabled, err := s.repo.GetDecryptedProviderConfig(ctx, tenantID, provider)
	if err != nil {
		return "", err
	}
	if !enabled {
		return "", ErrProviderNotEnabled
	}
	if clientID == "" {
		return "", ErrProviderNotConfigured
	}

	p, err := NewProvider(provider, clientID, clientSecret)
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

// HandleCallback completes a social sign-in and returns the engine's access
// token together with the destination to send the browser to.
//
// The state is consumed first, which both authenticates the callback as one the
// engine started and prevents replay. The provider profile then resolves to an
// account three ways: an existing link signs that user in, a matching email
// links the provider to that account, and neither creates a new user.
//
// The stored destination is re-validated here rather than trusted from the row,
// because this is the last point before a live token is handed to that host. An
// unauthorized destination degrades to an empty string, which makes the caller
// return the token in the response body instead of redirecting.
//
// Returns the access token and destination, or ErrStateNotFound,
// ErrStateExpired, ErrEmailRequired, a provider error, or a storage error.
func (s *Service) HandleCallback(
	ctx context.Context,
	tenantID, provider, stateToken, code string,
) (accessToken string, postCallbackRedirect string, err error) {
	state, err := s.repo.ConsumeSocialAuthState(ctx, tenantID, stateToken)
	if err != nil {
		return "", "", err
	}

	clientID, clientSecret, _, err := s.repo.GetDecryptedProviderConfig(ctx, tenantID, provider)
	if err != nil {
		return "", "", err
	}

	p, err := NewProvider(provider, clientID, clientSecret)
	if err != nil {
		return "", "", err
	}

	// The redirect URI presented at the token endpoint must be identical to the
	// one used to obtain the code; providers reject a mismatch.
	callbackURL := s.cfg.SocialCallbackURL(provider)
	token, err := p.ExchangeCode(ctx, code, callbackURL)
	if err != nil {
		return "", "", err
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
		return "", "", err
	}

	if providerUser.Email == "" {
		return "", "", ErrEmailRequired
	}

	var userID string
	var email string
	var name string
	var role string

	identity, err := s.repo.FindIdentityByProvider(ctx, provider, providerUser.ProviderUserID)
	if err != nil {
		return "", "", err
	}

	if identity != nil {
		fetchedUser, err := s.getUserByID(ctx, identity.UserID)
		if err != nil {
			return "", "", err
		}
		userID = fetchedUser.ID
		email = fetchedUser.Email
		name = fetchedUser.Name
	} else {
		existingUser, err := s.repo.FindUserByEmailForSocial(ctx, state.TenantID, state.Environment, providerUser.Email)
		if err != nil {
			return "", "", err
		}

		if existingUser != nil {
			userID = existingUser.ID
			email = existingUser.Email
			name = existingUser.Name
		} else {
			newUser, err := s.repo.CreateSocialUser(ctx, state.TenantID, state.Environment, providerUser.Email, providerUser.Name, providerUser.AvatarURL, providerUser.EmailVerified)
			if err != nil {
				return "", "", err
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

	jwtToken, err := jwtpkg.IssueAccessToken(userID, state.TenantID, string(state.Environment), email, name, role, s.cfg.EncryptionKey)
	if err != nil {
		return "", "", err
	}

	_, err = s.repo.UpsertIdentity(ctx, userID, provider, providerUser.ProviderUserID, providerUser.Email, providerUser.Name, providerUser.AvatarURL, providerUser.RawProfile, token.AccessToken, token.RefreshToken)
	if err != nil {
		return "", "", err
	}

	postCallback := state.PostCallbackRedirect
	if err := s.validatePostCallbackRedirect(ctx, state.TenantID, string(state.Environment), state.ApplicationID, postCallback); err != nil {
		if !errors.Is(err, ErrRedirectNotAllowed) {
			return "", "", err
		}
		postCallback = ""
	}

	return jwtToken, postCallback, nil
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
// Returns a storage error if the tenant's configuration cannot be read.
func (s *Service) GetSetupGuide(ctx context.Context, tenantID, provider string) ([]ProviderSetupResponse, error) {
	configs, err := s.repo.GetAllProviderConfigs(ctx, tenantID)
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
		p, err := NewProvider(pName, "x", "x")
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

// ConfigureProvider validates and stores a provider's credentials.
//
// The format check runs only when a secret is supplied, because an empty secret
// means "keep the stored one" rather than "clear it".
//
// Returns *ErrInvalidClientCredentials for a malformed credential, or a storage
// error.
func (s *Service) ConfigureProvider(
	ctx context.Context,
	tenantID, provider string,
	enabled bool,
	clientID, clientSecret string,
) error {
	if clientSecret != "" {
		if err := ValidateClientCredentials(provider, clientID, clientSecret); err != nil {
			return err
		}
	}
	return s.repo.SetProviderConfig(ctx, tenantID, provider, enabled, clientID, clientSecret)
}

// RemoveProvider deletes a provider's configuration for a tenant.
//
// Returns a storage error if the write fails.
func (s *Service) RemoveProvider(ctx context.Context, tenantID, provider string) error {
	return s.repo.DeleteProviderConfig(ctx, tenantID, provider)
}

// getUserByID loads a user by ID, returning an error if no such user exists.
func (s *Service) getUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}
