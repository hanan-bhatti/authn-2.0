/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/facebook.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Implements the IdentityProvider interface for Facebook OAuth2.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var _ IdentityProvider = (*FacebookProvider)(nil)

// FacebookProvider implements IdentityProvider for Facebook.
type FacebookProvider struct {
	clientID     string
	clientSecret string
}

// NewFacebookProvider constructs a new Facebook OAuth2 provider instance.
func NewFacebookProvider(clientID, clientSecret string) *FacebookProvider {
	return &FacebookProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Name returns the canonical provider identifier.
func (p *FacebookProvider) Name() string {
	return "facebook"
}

// AuthURL constructs the Facebook OAuth2 authorization URL.
func (p *FacebookProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  redirectURI,
		"state":         state,
		"scope":         "email public_profile",
		"response_type": "code",
	}
	return buildQueryString("https://www.facebook.com/v19.0/dialog/oauth", params)
}

// ExchangeCode trades the authorization code for tokens via GET request.
func (p *FacebookProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	params := map[string]string{
		"client_id":     p.clientID,
		"client_secret": p.clientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
	}
	tokenURL := buildQueryString("https://graph.facebook.com/v19.0/oauth/access_token", params)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create facebook token request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facebook token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read facebook response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("facebook token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse facebook token response: %w", err)
	}

	return &ProviderToken{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
	}, nil
}

// GetUserInfo fetches the user profile using Facebook Graph API.
func (p *FacebookProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.facebook.com/me?fields=id,name,email,picture", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create facebook userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("facebook userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read facebook userinfo response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("facebook userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var fbUser struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}
	if err := json.Unmarshal(body, &fbUser); err != nil {
		return nil, fmt.Errorf("failed to parse facebook userinfo response: %w", err)
	}

	var rawProfile map[string]interface{}
	_ = json.Unmarshal(body, &rawProfile)

	return &ProviderUser{
		ProviderUserID: fbUser.ID,
		Email:          fbUser.Email,
		EmailVerified:  false,
		Name:           fbUser.Name,
		AvatarURL:      fbUser.Picture.Data.URL,
		RawProfile:     rawProfile,
	}, nil
}

// SetupInstructions returns configuration guidance for developers.
func (p *FacebookProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://developers.facebook.com/apps",
		Steps: []string{
			"Go to developers.facebook.com/apps → Create App",
			"Add 'Facebook Login' product",
			"In Facebook Login → Settings, add Valid OAuth Redirect URI: " + callbackURL,
			"Copy App ID (client_id) and App Secret (client_secret) from App Settings → Basic",
		},
		ClientIDFormat:     "numeric App ID",
		ClientSecretFormat: "32-character hex string",
	}
}
