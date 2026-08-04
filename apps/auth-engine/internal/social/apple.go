/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/apple.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Apple Sign In identity provider implementation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AppleProvider implements IdentityProvider for Apple Sign In.
type AppleProvider struct {
	clientID     string
	clientSecret string
}

// NewAppleProvider creates a new Apple identity provider instance.
func NewAppleProvider(clientID, clientSecret string) *AppleProvider {
	return &AppleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Name returns the provider identifier.
func (p *AppleProvider) Name() string {
	return "apple"
}

// AuthURL constructs the Apple authorization URL.
func (p *AppleProvider) AuthURL(state, redirectURI string) string {
	params := map[string]string{
		"client_id":     p.clientID,
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"scope":         "name email",
		"state":         state,
		"response_mode": "form_post",
	}
	return buildQueryString("https://appleid.apple.com/auth/authorize", params)
}

// appleTokenResponse represents the JSON response from Apple's token endpoint.
type appleTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// ExchangeCode trades an authorization code for tokens with Apple.
func (p *AppleProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://appleid.apple.com/auth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("[apple] failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[apple] token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("[apple] failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[apple] token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp appleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("[apple] failed to decode token response: %w", err)
	}

	return &ProviderToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		IDToken:      tokenResp.IDToken,
	}, nil
}

// parseAppleIDToken parses Apple's id_token JWT and extracts the user claims.
func parseAppleIDToken(idToken string) (*ProviderUser, error) {
	return ParseAppleIDToken(idToken)
}

// ParseAppleIDToken parses Apple's id_token JWT and extracts sub and email.
func ParseAppleIDToken(idToken string) (*ProviderUser, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid id_token format")
	}

	payloadSegment := parts[1]
	if l := len(payloadSegment) % 4; l > 0 {
		payloadSegment += strings.Repeat("=", 4-l)
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		payloadBytes, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode id_token payload: %w", err)
		}
	}

	var rawProfile map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &rawProfile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal id_token claims: %w", err)
	}

	sub, _ := rawProfile["sub"].(string)
	email, _ := rawProfile["email"].(string)

	return &ProviderUser{
		ProviderUserID: sub,
		Email:          email,
		Name:           "",
		RawProfile:     rawProfile,
	}, nil
}

// GetUserInfo returns an error because Apple does not provide a userinfo endpoint.
func (p *AppleProvider) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error) {
	return nil, fmt.Errorf("apple does not provide a userinfo endpoint; use ExchangeCode id_token instead")
}

// SetupInstructions returns setup instructions for Apple Sign In.
func (p *AppleProvider) SetupInstructions(callbackURL string) ProviderSetup {
	return ProviderSetup{
		CallbackURL: callbackURL,
		ConsoleURL:  "https://developer.apple.com/account/resources/identifiers/list/serviceId",
		Steps: []string{
			"Go to developer.apple.com → Certificates, Identifiers & Profiles → Identifiers",
			"Create a Services ID (this is your client_id, e.g. com.yourapp.auth)",
			"Enable 'Sign In with Apple', configure the domain and add Return URL: " + callbackURL,
			"Create a Key with 'Sign In with Apple' capability — download the .p8 file",
			"Generate the client_secret JWT using your Team ID, Key ID, and .p8 file",
			"Paste the Services ID as Client ID and the generated JWT as Client Secret",
		},
		ClientIDFormat:     "reverse-domain Services ID (e.g. com.yourapp.auth)",
		ClientSecretFormat: "signed JWT generated from your Apple .p8 private key",
	}
}
