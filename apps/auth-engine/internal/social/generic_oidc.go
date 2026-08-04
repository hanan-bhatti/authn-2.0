/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/generic_oidc.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Generic OpenID Connect (OIDC) identity provider driver for custom/enterprise OIDC providers.
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

// GenericOIDCProvider implements IdentityProvider for any compliant OpenID Connect provider.
type GenericOIDCProvider struct {
	name         string
	clientID     string
	clientSecret string
	issuerURL    string
}

// NewGenericOIDCProvider creates a new GenericOIDCProvider instance.
func NewGenericOIDCProvider(name, clientID, clientSecret, issuerURL string) *GenericOIDCProvider {
	return &GenericOIDCProvider{
		name:         name,
		clientID:     clientID,
		clientSecret: clientSecret,
		issuerURL:    issuerURL,
	}
}

// Name returns the custom provider identifier.
func (p *GenericOIDCProvider) Name() string {
	return p.name
}

// AuthURL constructs the authorization URL for the generic OIDC provider.
func (p *GenericOIDCProvider) AuthURL(state, redirectURI string) string {
	baseURL := strings.TrimRight(p.issuerURL, "/") + "/authorize"
	params := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"scope":         "openid email profile",
		"state":         state,
	}
	return buildQueryString(baseURL, params)
}

// genericOIDCTokenResponse represents the JSON response from an OIDC token endpoint.
type genericOIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// ExchangeCode trades an authorization code for tokens with the generic OIDC provider.
func (p *GenericOIDCProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	tokenURL := strings.TrimRight(p.issuerURL, "/") + "/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to create token request: %w", p.name, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[%s] token exchange request failed: %w", p.name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to read response body: %w", p.name, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[%s] token exchange failed with status %d: %s", p.name, resp.StatusCode, string(body))
	}

	var tokenResp genericOIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("[%s] failed to decode token response: %w", p.name, err)
	}

	return &ProviderToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		IDToken:      tokenResp.IDToken,
	}, nil
}

// genericOIDCUserResponse represents the JSON response from an OIDC userinfo endpoint.
type genericOIDCUserResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// GetUserInfo fetches the authenticated user's profile from the OIDC userinfo endpoint.
func (p *GenericOIDCProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	userInfoURL := strings.TrimRight(p.issuerURL, "/") + "/userinfo"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to create userinfo request: %w", p.name, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[%s] userinfo request failed: %w", p.name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("[%s] failed to read userinfo response body: %w", p.name, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[%s] userinfo request failed with status %d: %s", p.name, resp.StatusCode, string(body))
	}

	var rawProfile map[string]interface{}
	if err := json.Unmarshal(body, &rawProfile); err != nil {
		return nil, fmt.Errorf("[%s] failed to decode raw userinfo profile: %w", p.name, err)
	}

	var userResp genericOIDCUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, fmt.Errorf("[%s] failed to decode userinfo response: %w", p.name, err)
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

// SetupInstructions returns setup instructions for generic OIDC provider.
func (p *GenericOIDCProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "",
		Steps: []string{
			"Configure your OIDC provider to allow redirect URI: " + callbackURL,
			"Set the application type to 'Web' or 'Regular Web Application'",
			"Copy the Client ID and Client Secret",
			"Set the Issuer URL to your provider's base URL (e.g. https://your-domain.okta.com)",
		},
		ClientIDFormat:     "varies by provider",
		ClientSecretFormat: "varies by provider",
	}
}
