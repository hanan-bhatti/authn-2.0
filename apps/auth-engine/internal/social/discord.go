/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/discord.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Implements the IdentityProvider interface for Discord OAuth2.
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

var _ IdentityProvider = (*DiscordProvider)(nil)

// DiscordProvider implements IdentityProvider for Discord.
type DiscordProvider struct {
	clientID     string
	clientSecret string
}

// NewDiscordProvider constructs a new Discord OAuth2 provider instance.
func NewDiscordProvider(clientID, clientSecret string) *DiscordProvider {
	return &DiscordProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Name returns the canonical provider identifier.
func (p *DiscordProvider) Name() string {
	return "discord"
}

// AuthURL constructs the Discord OAuth2 authorization URL.
func (p *DiscordProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"scope":         "identify email",
		"state":         state,
	}
	return buildQueryString("https://discord.com/api/oauth2/authorize", params)
}

// ExchangeCode trades the authorization code for tokens.
func (p *DiscordProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://discord.com/api/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create discord token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read discord response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discord token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse discord token response: %w", err)
	}

	return &ProviderToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}, nil
}

// GetUserInfo fetches the user profile using the access token.
func (p *DiscordProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discord userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read discord userinfo response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discord userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var discordUser struct {
		ID       string  `json:"id"`
		Username string  `json:"username"`
		Email    string  `json:"email"`
		Verified bool    `json:"verified"`
		Avatar   *string `json:"avatar"`
	}
	if err := json.Unmarshal(body, &discordUser); err != nil {
		return nil, fmt.Errorf("failed to parse discord userinfo response: %w", err)
	}

	var rawProfile map[string]interface{}
	_ = json.Unmarshal(body, &rawProfile)

	avatarURL := ""
	if discordUser.Avatar != nil && *discordUser.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", discordUser.ID, *discordUser.Avatar)
	}

	return &ProviderUser{
		ProviderUserID: discordUser.ID,
		Email:          discordUser.Email,
		EmailVerified:  discordUser.Verified,
		Name:           discordUser.Username,
		AvatarURL:      avatarURL,
		RawProfile:     rawProfile,
	}, nil
}

// SetupInstructions returns configuration guidance for developers.
func (p *DiscordProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://discord.com/developers/applications",
		Steps: []string{
			"Go to discord.com/developers/applications",
			"Click 'New Application'",
			"Go to OAuth2 → Redirects → Add: " + callbackURL,
			"Copy Client ID and Client Secret from OAuth2 tab",
		},
		ClientIDFormat:     "numeric Snowflake ID",
		ClientSecretFormat: "32-character alphanumeric",
	}
}
