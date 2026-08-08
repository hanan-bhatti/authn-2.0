/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/service.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Orchestration layer for social OAuth2 flows — authorize initiation,
 *              callback handling (find/create/link user), setup guide generation,
 *              and provider config management.
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
	ErrProviderNotEnabled    = errors.New("social provider not enabled for this tenant")
	ErrProviderNotConfigured = errors.New("social provider not configured for this tenant")
	ErrEmailConflict         = errors.New("an account with this email already exists; sign in with your original method then link providers in account settings")
	ErrEmailRequired         = errors.New("provider did not return an email address; cannot create account")
	ErrProviderAuthFailed    = errors.New("social provider authentication failed")
	ErrRedirectNotAllowed    = errors.New("post_callback_redirect is not an authorized redirect target for this application")
)

// validatePostCallbackRedirect checks a caller-supplied post-callback destination
// against the initiating Application's registered exact_redirect_uris.
//
// Audit H5(c) — open redirect carrying a live access token. post_callback_redirect
// arrives as a raw query parameter on GET /v1/client/auth/social/:provider/authorize,
// is persisted verbatim into social_auth_state, and was handed straight to
// c.Redirect() by the callback handler alongside a freshly issued JWT. The
// authorize endpoint is publishable-key authenticated, and a publishable key is
// public by design, so anyone able to start a social login could name their own
// host and have the victim's browser deliver a live token to it.
//
// The allowlist reused here is application.exact_redirect_uris — the same
// registration record internal/oauth's ValidateClientApplication checks
// redirect_uri against (internal/oauth/service.go), and the allowlist the
// social_auth_state schema comment already claims is enforced.
//
// A destination is accepted when it matches a registered URI exactly, or when it
// is same-origin (scheme + host + port) with one. The origin relaxation is what
// lets an application register "https://app.example.com/callback" and still land
// the user on "https://app.example.com/dashboard"; it cannot move the token off
// the application's own origin, which is the property that matters here.
//
// Fails closed: an unparseable target, a non-http(s) scheme, a scheme-relative
// URL, a missing application registration, or an empty allowlist all reject.
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

	// "javascript:alert(1)", "//evil.com/x" and "/dashboard" all parse without
	// error, so an explicit absolute-http(s) check is required before comparing.
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return ErrRedirectNotAllowed
	}

	// No registered application means there is no allowlist to satisfy.
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

type Service struct {
	repo *Repository
	cfg  *config.Config
}

func NewService(repo *Repository, cfg *config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
}

// InitiateAuthorize generates a CSRF state token, persists it, and returns the
// provider's authorization URL to redirect the browser to.
//
// Called by: GET /v1/client/auth/social/:provider/authorize
//
// Returns: (authorizationURL string, err error)
func (s *Service) InitiateAuthorize(
	ctx context.Context,
	tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect string,
) (string, error) {
	// Reject an unregistered post-callback destination before anything else
	// happens — no provider config read, no state row written. See
	// validatePostCallbackRedirect for the H5(c) open-redirect rationale.
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

	stateToken, err := s.repo.CreateSocialAuthState(ctx, tenantID, applicationID, environment, provider, redirectURI, postCallbackRedirect)
	if err != nil {
		return "", err
	}

	callbackURL := s.cfg.SocialCallbackURL(provider)
	authURL := p.AuthURL(stateToken, callbackURL)

	return authURL, nil
}

// HandleCallback processes the OAuth2 callback from a social provider.
// It validates the state, exchanges the code for tokens, fetches the user profile,
// and either logs in an existing user or creates a new one.
//
// Called by: GET /v1/client/auth/social/:provider/callback?code=...&state=...
//
// Returns: accessToken (our JWT), postCallbackRedirect URL, and any error.
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

	callbackURL := s.cfg.SocialCallbackURL(provider)
	token, err := p.ExchangeCode(ctx, code, callbackURL)
	if err != nil {
		return "", "", err
	}

	var providerUser *ProviderUser
	if provider == "apple" && token.IDToken != "" {
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
		// Existing social user — LOGIN path
		fetchedUser, err := s.getUserByID(ctx, identity.UserID)
		if err != nil {
			return "", "", err
		}
		userID = fetchedUser.ID
		email = fetchedUser.Email
		name = fetchedUser.Name
	} else {
		// Check email collision
		existingUser, err := s.repo.FindUserByEmailForSocial(ctx, state.TenantID, state.Environment, providerUser.Email)
		if err != nil {
			return "", "", err
		}

		if existingUser != nil {
			// Link identity to existing user
			userID = existingUser.ID
			email = existingUser.Email
			name = existingUser.Name
		} else {
			// Brand new user — SIGNUP path
			newUser, err := s.repo.CreateSocialUser(ctx, state.TenantID, state.Environment, providerUser.Email, providerUser.Name, providerUser.AvatarURL, providerUser.EmailVerified)
			if err != nil {
				return "", "", err
			}
			userID = newUser.ID
			email = newUser.Email
			name = newUser.Name
		}
	}

	// Resolve the console role claim from recorded roles. A social login can be
	// a tenant admin returning through Google/GitHub, so hardcoding "" here
	// stripped their console privilege. A brand-new user has no roles yet and
	// resolves to "" naturally.
	role = rbac.ResolveConsoleRoleClaim(ctx, s.repo.factory.GetClient(ctx, "", ""), userID)

	jwtToken, err := jwtpkg.IssueAccessToken(userID, state.TenantID, string(state.Environment), email, name, role, s.cfg.EncryptionKey)
	if err != nil {
		return "", "", err
	}

	_, err = s.repo.UpsertIdentity(ctx, userID, provider, providerUser.ProviderUserID, providerUser.Email, providerUser.Name, providerUser.AvatarURL, providerUser.RawProfile, token.AccessToken, token.RefreshToken)
	if err != nil {
		return "", "", err
	}

	// Re-validate the stored destination at redemption time rather than trusting
	// the row. State rows persisted before the H5(c) fix landed carry unvalidated
	// destinations, and this is the last point before a live JWT is handed to
	// that host. An unauthorized destination degrades to the JSON response
	// (token returned in the body to the caller) instead of redirecting.
	postCallback := state.PostCallbackRedirect
	if err := s.validatePostCallbackRedirect(ctx, state.TenantID, string(state.Environment), state.ApplicationID, postCallback); err != nil {
		if !errors.Is(err, ErrRedirectNotAllowed) {
			return "", "", err
		}
		postCallback = ""
	}

	return jwtToken, postCallback, nil
}

type ProviderSetupResponse struct {
	Provider   string        `json:"provider"`
	Enabled    bool          `json:"enabled"`
	ClientID   string        `json:"client_id"`
	Configured bool          `json:"configured"`
	Setup      ProviderSetup `json:"setup"`
}

// GetSetupGuide returns the setup instructions and current config (secrets masked)
// for a specific provider, or for all supported providers if provider=="".
// Used by: GET /v1/tenant/social-providers and GET /v1/tenant/social-providers/:provider
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

// ConfigureProvider validates and saves a provider's credentials.
// Called by: PUT /v1/tenant/social-providers/:provider
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

// RemoveProvider deletes a provider's configuration entirely.
// Called by: DELETE /v1/tenant/social-providers/:provider
func (s *Service) RemoveProvider(ctx context.Context, tenantID, provider string) error {
	return s.repo.DeleteProviderConfig(ctx, tenantID, provider)
}

func (s *Service) getUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}
