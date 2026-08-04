/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/google.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Google OAuth2 / OIDC identity provider implementation.
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

// Ensure GoogleProvider implements IdentityProvider interface.
var _ IdentityProvider = (*GoogleProvider)(nil)

// GoogleProvider implements the IdentityProvider interface for Google OAuth2/OIDC.
type GoogleProvider struct {
	clientID     string
	clientSecret string
}

// NewGoogleProvider initializes a new Google social identity provider.
func NewGoogleProvider(clientID, clientSecret string) *GoogleProvider {
	return &GoogleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Name returns the canonical identifier for Google.
func (p *GoogleProvider) Name() string {
	return "google"
}

// AuthURL constructs the Google authorization URL for user consent.
func (p *GoogleProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"scope":         "openid email profile",
		"state":         state,
		"access_type":   "offline",
		"prompt":        "consent",
	}
	return buildQueryString("https://accounts.google.com/o/oauth2/v2/auth", params)
}

// ExchangeCode trades the authorization code for access and refresh tokens.
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://oauth2.googleapis.com/token",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create google token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read google token response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("google token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("failed to parse google token response: %w", err)
	}

	return &ProviderToken{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		TokenType:    res.TokenType,
		ExpiresIn:    res.ExpiresIn,
		IDToken:      res.IDToken,
	}, nil
}

// GetUserInfo fetches the user's profile information from Google using the access token.
func (p *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://www.googleapis.com/oauth2/v3/userinfo",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create google userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read google userinfo response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("google get user info failed (%d): %s", resp.StatusCode, string(body))
	}

	var rawProfile map[string]interface{}
	if err := json.Unmarshal(body, &rawProfile); err != nil {
		return nil, fmt.Errorf("failed to parse google raw profile: %w", err)
	}

	var userInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse google userinfo response: %w", err)
	}

	return &ProviderUser{
		ProviderUserID: userInfo.Sub,
		Email:          userInfo.Email,
		EmailVerified: userInfo.EmailVerified,
		Name:           userInfo.Name,
		AvatarURL:      userInfo.Picture,
		RawProfile:     rawProfile,
	}, nil
}

// SetupInstructions returns configuration guidance for setting up Google OAuth.
func (p *GoogleProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://console.cloud.google.com/apis/credentials",
		Steps: []string{
			"Go to console.cloud.google.com → APIs & Services → Credentials",
			"Click 'Create Credentials' → OAuth 2.0 Client ID",
			"Set Application type to 'Web application'",
			"Under 'Authorized redirect URIs' add: " + callbackURL,
			"Copy the Client ID and Client Secret into Authn",
		},
		ClientIDFormat:     "must end with .apps.googleusercontent.com",
		ClientSecretFormat: "starts with GOCSPX- (newer apps) or alphanumeric",
	}
}
