/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/social/factory.go
 * Tier: Social Identity Provider Layer
 *
 * Description: Provider factory — constructs an IdentityProvider implementation
 *              by name using decrypted credentials. This is the single call site
 *              that maps a provider name string (from Tenant.social_providers) to
 *              a concrete driver. Adding a new provider only requires registering
 *              it here.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package social

import (
	"fmt"
	"strings"
)

// NewProvider constructs the IdentityProvider for the given provider name.
// clientID and clientSecret are the plaintext credentials (caller is responsible
// for decrypting clientSecretEncrypted before calling this).
//
// For GenericOIDC, pass the issuerURL as extraParam.
// For Microsoft, pass the Azure tenant ID as extraParam (defaults to "common").
//
// Returns ErrUnknownProvider if the provider name is not recognized.
func NewProvider(name, clientID, clientSecret string, extraParam ...string) (IdentityProvider, error) {
	extra := ""
	if len(extraParam) > 0 {
		extra = strings.TrimSpace(extraParam[0])
	}

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "google":
		return NewGoogleProvider(clientID, clientSecret), nil
	case "github":
		return NewGitHubProvider(clientID, clientSecret), nil
	case "discord":
		return NewDiscordProvider(clientID, clientSecret), nil
	case "microsoft":
		tenantID := extra
		if tenantID == "" {
			tenantID = "common"
		}
		return NewMicrosoftProvider(clientID, clientSecret, tenantID), nil
	case "apple":
		return NewAppleProvider(clientID, clientSecret), nil
	case "facebook":
		return NewFacebookProvider(clientID, clientSecret), nil
	case "x", "twitter":
		return NewXProvider(clientID, clientSecret), nil
	case "linkedin":
		return NewLinkedInProvider(clientID, clientSecret), nil
	default:
		// Treat any unknown name as a Generic OIDC provider if an issuer URL is given.
		if extra != "" {
			return NewGenericOIDCProvider(name, clientID, clientSecret, extra), nil
		}
		return nil, &ErrUnknownProvider{Name: name}
	}
}

// SupportedProviders returns the canonical names of all built-in providers.
// Used by the admin API to return setup instructions for all providers,
// even those not yet configured by the tenant.
func SupportedProviders() []string {
	return []string{
		"google",
		"github",
		"discord",
		"microsoft",
		"apple",
		"facebook",
		"x",
		"linkedin",
	}
}

// ValidateClientCredentials performs provider-specific format validation on the
// client_id and client_secret supplied by the tenant admin.
// Returns nil if valid, *ErrInvalidClientCredentials otherwise.
func ValidateClientCredentials(provider, clientID, clientSecret string) error {
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)

	if clientID == "" {
		return &ErrInvalidClientCredentials{Provider: provider, Field: "client_id", Reason: "must not be empty"}
	}
	if clientSecret == "" {
		return &ErrInvalidClientCredentials{Provider: provider, Field: "client_secret", Reason: "must not be empty"}
	}

	switch strings.ToLower(provider) {
	case "google":
		if !strings.HasSuffix(clientID, ".apps.googleusercontent.com") {
			return &ErrInvalidClientCredentials{
				Provider: provider,
				Field:    "client_id",
				Reason:   "must end with .apps.googleusercontent.com",
			}
		}
	case "github":
		// GitHub client IDs are 20-char alphanumeric or start with "Iv1." for GitHub Apps
		if len(clientID) < 10 {
			return &ErrInvalidClientCredentials{
				Provider: provider,
				Field:    "client_id",
				Reason:   "must be a valid GitHub OAuth App client ID (20+ characters)",
			}
		}
		if len(clientSecret) < 20 {
			return &ErrInvalidClientCredentials{
				Provider: provider,
				Field:    "client_secret",
				Reason:   "GitHub client secrets are at least 40 hex characters",
			}
		}
	case "discord":
		// Discord client IDs are numeric Snowflake IDs
		for _, ch := range clientID {
			if ch < '0' || ch > '9' {
				return &ErrInvalidClientCredentials{
					Provider: provider,
					Field:    "client_id",
					Reason:   "Discord client IDs are numeric Snowflake IDs",
				}
			}
		}
	case "microsoft":
		// Microsoft Application IDs are UUID v4
		if len(clientID) != 36 || strings.Count(clientID, "-") != 4 {
			return &ErrInvalidClientCredentials{
				Provider: provider,
				Field:    "client_id",
				Reason:   "must be a valid UUID v4 (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
			}
		}
	case "apple":
		// Apple Services IDs use reverse-domain format e.g. com.yourapp.auth
		if !strings.Contains(clientID, ".") {
			return &ErrInvalidClientCredentials{
				Provider: provider,
				Field:    "client_id",
				Reason:   "must be a reverse-domain Services ID (e.g. com.yourapp.auth)",
			}
		}
		// facebook, x, linkedin, generic_oidc: only the empty-string check above
	}

	return nil
}

// ErrUnknownProvider reports a provider name that maps to no built-in driver
// and carried no issuer URL to be treated as generic OIDC.
type ErrUnknownProvider struct {
	// Name is the unrecognized provider name as supplied by the caller.
	Name string
}

// Error names the unrecognized provider and lists the supported ones.
func (e *ErrUnknownProvider) Error() string {
	return fmt.Sprintf("unknown social provider: %q — supported: %s", e.Name, strings.Join(SupportedProviders(), ", "))
}
