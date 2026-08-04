/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/microsoft.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Implements the IdentityProvider interface for Microsoft OAuth2/OIDC.
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

var _ IdentityProvider = (*MicrosoftProvider)(nil)

// MicrosoftProvider implements IdentityProvider for Microsoft Entra / MSA.
type MicrosoftProvider struct {
	clientID     string
	clientSecret string
	tenantID     string
}

// NewMicrosoftProvider constructs a new Microsoft OAuth2 provider instance.
// tenantID defaults to "common" if empty to support multi-tenant applications.
func NewMicrosoftProvider(clientID, clientSecret, tenantID string) *MicrosoftProvider {
	if tenantID == "" {
		tenantID = "common"
	}
	return &MicrosoftProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		tenantID:     tenantID,
	}
}

// Name returns the canonical provider identifier.
func (p *MicrosoftProvider) Name() string {
	return "microsoft"
}

// AuthURL constructs the Microsoft OAuth2 authorization URL.
func (p *MicrosoftProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"scope":         "openid email profile offline_access",
		"state":         state,
	}
	baseURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", p.tenantID)
	return buildQueryString(baseURL, params)
}

// ExchangeCode trades the authorization code for tokens.
func (p *MicrosoftProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", p.tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create microsoft token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read microsoft response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("microsoft token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse microsoft token response: %w", err)
	}

	return &ProviderToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		IDToken:      tokenResp.IDToken,
	}, nil
}

// GetUserInfo fetches the user profile using Microsoft Graph API.
func (p *MicrosoftProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create microsoft userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read microsoft userinfo response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("microsoft userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var msUser struct {
		ID                string `json:"id"`
		UserPrincipalName string `json:"userPrincipalName"`
		DisplayName       string `json:"displayName"`
		Mail              string `json:"mail"`
	}
	if err := json.Unmarshal(body, &msUser); err != nil {
		return nil, fmt.Errorf("failed to parse microsoft userinfo response: %w", err)
	}

	var rawProfile map[string]interface{}
	_ = json.Unmarshal(body, &rawProfile)

	email := msUser.Mail
	if email == "" {
		email = msUser.UserPrincipalName
	}

	return &ProviderUser{
		ProviderUserID: msUser.ID,
		Email:          email,
		EmailVerified:  true,
		Name:           msUser.DisplayName,
		RawProfile:     rawProfile,
	}, nil
}

// SetupInstructions returns configuration guidance for developers.
func (p *MicrosoftProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps",
		Steps: []string{
			"Go to portal.azure.com → Azure Active Directory → App registrations",
			"Click 'New registration'",
			"Under 'Redirect URIs' add Web platform URI: " + callbackURL,
			"Go to 'Certificates & secrets' → New client secret",
			"Copy the Application (client) ID and client secret",
		},
		ClientIDFormat:     "UUID v4 (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
		ClientSecretFormat: "alphanumeric with special chars, shown only once at creation",
	}
}
