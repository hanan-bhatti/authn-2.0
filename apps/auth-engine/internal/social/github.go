/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/github.go
 * Tier: Social Identity Provider Layer
 *
 * Description: GitHub OAuth2 identity provider implementation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// Ensure GitHubProvider implements IdentityProvider interface.
var _ IdentityProvider = (*GitHubProvider)(nil)

// GitHubProvider implements the IdentityProvider interface for GitHub OAuth2.
type GitHubProvider struct {
	clientID     string
	clientSecret string
}

// NewGitHubProvider initializes a new GitHub social identity provider.
func NewGitHubProvider(clientID, clientSecret string) *GitHubProvider {
	return &GitHubProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Name returns the canonical identifier for GitHub.
func (p *GitHubProvider) Name() string {
	return "github"
}

// AuthURL constructs the GitHub authorization URL for user consent.
func (p *GitHubProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":    p.clientID,
		"redirect_uri": redirectURI,
		"scope":        "read:user user:email",
		"state":        state,
	}
	return buildQueryString("https://github.com/login/oauth/authorize", params)
}

// ExchangeCode trades the authorization code for access tokens.
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	reqBody, err := json.Marshal(map[string]string{
		"client_id":     p.clientID,
		"client_secret": p.clientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal github token request body: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://github.com/login/oauth/access_token",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create github token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github token response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("failed to parse github token response: %w", err)
	}

	if res.Error != "" {
		return nil, fmt.Errorf("github token exchange error: %s (%s)", res.Error, res.ErrorDesc)
	}

	return &ProviderToken{
		AccessToken:  res.AccessToken,
		TokenType:    res.TokenType,
		RefreshToken: "",
		ExpiresIn:    0,
		IDToken:      "",
	}, nil
}

// GetUserInfo fetches the user's profile and primary email from GitHub using the access token.
func (p *GitHubProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	// 1. Fetch user profile
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.github.com/user",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create github user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github user request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github user response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github get user info failed (%d): %s", resp.StatusCode, string(body))
	}

	var rawProfile map[string]interface{}
	if err := json.Unmarshal(body, &rawProfile); err != nil {
		return nil, fmt.Errorf("failed to parse github raw profile: %w", err)
	}

	var userInfo struct {
		ID        int64  `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
		Login     string `json:"login"`
	}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse github user response: %w", err)
	}

	name := userInfo.Name
	if name == "" {
		name = userInfo.Login
	}

	email := userInfo.Email
	emailVerified := false
	if email != "" {
		emailVerified = true
	}

	// 2. If email is empty, fetch user emails list to find primary & verified email
	if email == "" {
		emailReq, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			"https://api.github.com/user/emails",
			nil,
		)
		if err == nil {
			emailReq.Header.Set("Authorization", "Bearer "+accessToken)
			emailReq.Header.Set("Accept", "application/vnd.github+json")

			emailResp, err := http.DefaultClient.Do(emailReq)
			if err == nil {
				defer emailResp.Body.Close()
				if emailResp.StatusCode >= 200 && emailResp.StatusCode < 300 {
					emailBody, err := io.ReadAll(emailResp.Body)
					if err == nil {
						var emails []struct {
							Email    string `json:"email"`
							Primary  bool   `json:"primary"`
							Verified bool   `json:"verified"`
						}
						if json.Unmarshal(emailBody, &emails) == nil {
							for _, e := range emails {
								if e.Primary && e.Verified {
									email = e.Email
									emailVerified = true
									break
								}
							}
						}
					}
				}
			}
		}
	}

	return &ProviderUser{
		ProviderUserID: strconv.FormatInt(userInfo.ID, 10),
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           name,
		AvatarURL:      userInfo.AvatarURL,
		RawProfile:     rawProfile,
	}, nil
}

// SetupInstructions returns configuration guidance for setting up GitHub OAuth.
func (p *GitHubProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://github.com/settings/developers",
		Steps: []string{
			"Go to github.com/settings/developers → OAuth Apps",
			"Click 'New OAuth App'",
			"Set 'Authorization callback URL' to: " + callbackURL,
			"Copy the Client ID and generate a Client Secret",
		},
		ClientIDFormat:     "20-character alphanumeric string (may start with Iv1. for GitHub Apps)",
		ClientSecretFormat: "40-character hex string",
	}
}
