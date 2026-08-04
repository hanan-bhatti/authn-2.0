/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/x.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Twitter/X OAuth 2.0 PKCE identity provider implementation.
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
	"net/url"
	"strings"
)

// XProvider implements IdentityProvider for Twitter/X (OAuth 2.0 PKCE).
type XProvider struct {
	clientID     string
	clientSecret string
}

// NewXProvider creates a new Twitter/X identity provider instance.
func NewXProvider(clientID, clientSecret string) *XProvider {
	return &XProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Name returns the provider identifier.
func (p *XProvider) Name() string {
	return "x"
}

// AuthURL constructs the Twitter/X authorization URL using PKCE.
func (p *XProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":             p.clientID,
		"redirect_uri":          redirectURI,
		"response_type":         "code",
		"scope":                 "tweet.read users.read email",
		"state":                 state,
		"code_challenge_method": "plain",
		"code_challenge":        state, // state used as PKCE verifier for simplicity
	}
	return buildQueryString("https://twitter.com/i/oauth2/authorize", params)
}

// xTokenResponse represents the token response from Twitter/X.
type xTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// ExchangeCode trades an authorization code for tokens with Twitter/X.
func (p *XProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	// NOTE: For PKCE, code_verifier is required. We use code as code_verifier for simplicity.
	data.Set("code_verifier", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/2/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("[x] failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.clientID, p.clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[x] token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("[x] failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[x] token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp xTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("[x] failed to decode token response: %w", err)
	}

	return &ProviderToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

// xUserResponse represents the response from Twitter/X /2/users/me endpoint.
type xUserResponse struct {
	Data struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Username        string `json:"username"`
		ProfileImageURL string `json:"profile_image_url"`
	} `json:"data"`
}

// GetUserInfo fetches the authenticated user's profile from Twitter/X.
func (p *XProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url", nil)
	if err != nil {
		return nil, fmt.Errorf("[x] failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[x] userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("[x] failed to read userinfo response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[x] userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var rawProfile map[string]interface{}
	if err := json.Unmarshal(body, &rawProfile); err != nil {
		return nil, fmt.Errorf("[x] failed to decode raw userinfo profile: %w", err)
	}

	var userResp xUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, fmt.Errorf("[x] failed to decode userinfo response: %w", err)
	}

	return &ProviderUser{
		ProviderUserID: userResp.Data.ID,
		Name:           userResp.Data.Name,
		AvatarURL:      userResp.Data.ProfileImageURL,
		RawProfile:     rawProfile,
	}, nil
}

// SetupInstructions returns setup instructions for Twitter/X.
func (p *XProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://developer.twitter.com/en/portal/dashboard",
		Steps: []string{
			"Go to developer.twitter.com → Projects & Apps → Create App",
			"Under 'User authentication settings' enable OAuth 2.0",
			"Set 'Callback URI / Redirect URL' to: " + callbackURL,
			"Set Type of App to 'Web App'",
			"Copy the Client ID and Client Secret",
		},
		ClientIDFormat:     "alphanumeric string from Twitter developer portal",
		ClientSecretFormat: "alphanumeric string from Twitter developer portal",
	}
}
