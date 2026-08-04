/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/linkedin.go
 * Tier: Social Identity Provider Layer
 *
 * Description: LinkedIn OpenID Connect identity provider implementation.
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

// LinkedInProvider implements IdentityProvider for LinkedIn using OpenID Connect.
type LinkedInProvider struct {
	clientID     string
	clientSecret string
}

// NewLinkedInProvider creates a new LinkedIn identity provider instance.
func NewLinkedInProvider(clientID, clientSecret string) *LinkedInProvider {
	return &LinkedInProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Name returns the provider identifier.
func (p *LinkedInProvider) Name() string {
	return "linkedin"
}

// AuthURL constructs the LinkedIn authorization URL.
func (p *LinkedInProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"scope":         "openid profile email",
		"state":         state,
	}
	return buildQueryString("https://www.linkedin.com/oauth/v2/authorization", params)
}

// linkedInTokenResponse represents the token response from LinkedIn.
type linkedInTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// ExchangeCode trades an authorization code for tokens with LinkedIn.
func (p *LinkedInProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.linkedin.com/oauth/v2/accessToken", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("[linkedin] failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[linkedin] token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("[linkedin] failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[linkedin] token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp linkedInTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("[linkedin] failed to decode token response: %w", err)
	}

	return &ProviderToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

// linkedInUserResponse represents the response from LinkedIn's OpenID Connect userinfo endpoint.
type linkedInUserResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// GetUserInfo fetches the authenticated user's profile from LinkedIn's userinfo endpoint.
func (p *LinkedInProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.linkedin.com/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("[linkedin] failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[linkedin] userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("[linkedin] failed to read userinfo response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[linkedin] userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var rawProfile map[string]interface{}
	if err := json.Unmarshal(body, &rawProfile); err != nil {
		return nil, fmt.Errorf("[linkedin] failed to decode raw userinfo profile: %w", err)
	}

	var userResp linkedInUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, fmt.Errorf("[linkedin] failed to decode userinfo response: %w", err)
	}

	return &ProviderUser{
		ProviderUserID: userResp.Sub,
		Email:          userResp.Email,
		EmailVerified:  userResp.EmailVerified,
		Name:           userResp.Name,
		AvatarURL:      userResp.Picture,
		RawProfile:     rawProfile,
	}, nil
}

// SetupInstructions returns setup instructions for LinkedIn.
func (p *LinkedInProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://www.linkedin.com/developers/apps",
		Steps: []string{
			"Go to linkedin.com/developers/apps → Create App",
			"Under 'Auth' tab, add Authorized redirect URL: " + callbackURL,
			"Request 'Sign In with LinkedIn using OpenID Connect' product",
			"Copy Client ID and Client Secret from Auth tab",
		},
		ClientIDFormat:     "alphanumeric string",
		ClientSecretFormat: "alphanumeric string",
	}
}
