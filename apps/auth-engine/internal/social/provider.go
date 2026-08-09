/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/provider.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Core interface and shared data models for social OAuth2/OIDC
 *              identity provider drivers. Each provider (Google, GitHub, Discord,
 *              etc.) implements IdentityProvider. The handler and service layers
 *              only depend on this interface — adding a new provider never requires
 *              touching existing code.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// --------- Core Interface ---------

// IdentityProvider is the pluggable driver interface implemented by every social provider.
// All methods are stateless — provider config (client ID, secret, callback URL) is injected
// at construction time via NewProvider / the factory.
type IdentityProvider interface {
	// Name returns the canonical lowercase provider identifier used as the map key
	// in Tenant.social_providers and as the :provider URL path segment.
	// Examples: "google", "github", "discord", "microsoft", "apple", "facebook", "x", "linkedin"
	Name() string

	// AuthURL constructs the full provider authorization URL the browser should be
	// redirected to. state is the CSRF nonce stored in SocialAuthState. redirectURI
	// is cfg.SocialCallbackURL(provider) — the URL registered in the provider's console.
	AuthURL(state, redirectURI string) string

	// ExchangeCode trades the one-time authorization code (received in the callback)
	// for an access token and optional refresh token from the provider's token endpoint.
	ExchangeCode(ctx context.Context, code, redirectURI string) (*ProviderToken, error)

	// GetUserInfo fetches the authenticated user's profile from the provider using
	// the access token obtained via ExchangeCode. Returns a normalized ProviderUser.
	GetUserInfo(ctx context.Context, accessToken string) (*ProviderUser, error)

	// SetupInstructions returns human-readable steps (and the exact callback URL)
	// that a developer must configure in the provider's developer console.
	// Used by GET /v1/tenant/social-providers/:provider to power the setup UX.
	SetupInstructions(callbackURL string) ProviderSetup
}

// --------- Shared Data Models ---------

// ProviderToken holds the OAuth2 tokens returned by a provider's token endpoint.
type ProviderToken struct {
	AccessToken  string
	RefreshToken string // empty if provider does not issue refresh tokens
	TokenType    string // usually "Bearer"
	ExpiresIn    int    // seconds until access token expiry; 0 = unknown
	IDToken      string // OIDC id_token if provider is OIDC-capable (Google, Microsoft, Apple)
}

// ProviderUser holds the normalized user profile returned by a social provider.
// All fields are best-effort — providers vary in what they expose.
type ProviderUser struct {
	// ProviderUserID is the stable, unique subject identifier from the provider.
	// Use this (not email) as the join key in the Identity table — emails can change.
	ProviderUserID string

	// Email is the primary email address returned by the provider. May be empty
	// for providers that don't expose email (e.g. GitHub with private email setting).
	Email string

	// EmailVerified indicates whether the provider has verified this email address.
	// Only trust this flag from providers that explicitly set it (Google, Microsoft).
	// Default false for providers that don't return this claim.
	EmailVerified bool

	// Name is the display name / full name returned by the provider.
	Name string

	// AvatarURL is the profile picture URL. May be empty.
	AvatarURL string

	// RawProfile contains the full JSON claims map from the provider's userinfo
	// endpoint. Stored as-is in Identity.profile_data for future use.
	RawProfile map[string]interface{}
}

// ProviderSetup contains the information returned to developers to help them
// correctly configure the OAuth app in the provider's developer console.
type ProviderSetup struct {
	// CallbackURL is the exact URI to register as "Authorized redirect URI"
	// in the provider's console. Derived from AppBaseURL — never hardcoded.
	CallbackURL string `json:"callback_url"`

	// Steps is an ordered list of human-readable instructions.
	Steps []string `json:"step_by_step"`

	// ConsoleURL is the URL to the provider's developer console where the
	// OAuth app should be created.
	ConsoleURL string `json:"console_url"`

	// ClientIDFormat describes the expected format for validation hints.
	ClientIDFormat string `json:"client_id_format,omitempty"`

	// ClientSecretFormat describes the expected format for validation hints.
	ClientSecretFormat string `json:"client_secret_format,omitempty"`
}

// ProviderConfig holds the per-provider settings stored in Tenant.social_providers.
// This is the shape of each value in the JSON map.
type ProviderConfig struct {
	// Enabled reports whether the tenant has switched this provider on.
	Enabled bool `json:"enabled"`
	// ClientID is the provider-issued public client identifier.
	ClientID string `json:"client_id"`
	// ClientSecretEncrypted is the AES-256-GCM ciphertext of the client secret.
	// The plaintext is never stored and never leaves the service layer.
	ClientSecretEncrypted string `json:"client_secret_encrypted"`
}

// --------- Validation ---------

// ErrInvalidClientCredentials reports a client_id or client_secret that fails
// the format rules of a specific provider.
type ErrInvalidClientCredentials struct {
	// Provider is the provider the credential was rejected for.
	Provider string
	// Field names the offending credential, "client_id" or "client_secret".
	Field string
	// Reason is client-safe prose describing the expected format.
	Reason string
}

// Error renders the failure as "[provider] invalid field: reason". Every part
// is authored here, so the result is safe to return to an API caller.
func (e *ErrInvalidClientCredentials) Error() string {
	return fmt.Sprintf("[%s] invalid %s: %s", e.Provider, e.Field, e.Reason)
}

// --------- Shared helpers used by multiple providers ---------

// buildQueryString constructs a URL-encoded query string from a map of params.
func buildQueryString(base string, params map[string]string) string {
	u, _ := url.Parse(base)
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// scopeString joins a slice of OAuth scopes into a space-separated string.
func scopeString(scopes []string) string {
	return strings.Join(scopes, " ")
}
