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

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
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
)

type Service struct {
	repo *Repository
	cfg  *config.EnvConfig
}

func NewService(repo *Repository, cfg *config.EnvConfig) *Service {
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

	jwtToken, err := jwtpkg.IssueAccessToken(userID, state.TenantID, string(state.Environment), email, name, role, s.cfg.AuthnEncryptionKey)
	if err != nil {
		return "", "", err
	}

	_, err = s.repo.UpsertIdentity(ctx, userID, provider, providerUser.ProviderUserID, providerUser.Email, providerUser.Name, providerUser.AvatarURL, providerUser.RawProfile, token.AccessToken, token.RefreshToken)
	if err != nil {
		return "", "", err
	}

	return jwtToken, state.PostCallbackRedirect, nil
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
