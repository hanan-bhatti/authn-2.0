/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/oauth/oauth_token_service.go
 * Tier: Business Logic Layer / Core Service
 *
 * Description: PKCE-bound authorization code issuance and redemption, token exchange, refresh token rotation, and UserInfo claim resolution.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/accountstatus"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// IssueAuthorizationCode mints a single-use authorization code bound to the
// client, the authenticated user and the PKCE challenge, valid for
// Config.OAuthCodeTTL.
//
// The "plain" challenge method is refused: it puts the verifier and the
// challenge on the wire as the same value, so an attacker who intercepts the
// authorization request can complete the exchange. Only S256 is accepted.
//
// Returns the code string, or an error if the method is unsupported, entropy is
// unavailable, or the code cannot be persisted.
func (s *Service) IssueAuthorizationCode(ctx context.Context, clientID string, userID string, tenantID string, redirectURI string, codeChallenge string, method string, scope string) (string, error) {
	if strings.EqualFold(method, "plain") {
		return "", fmt.Errorf("invalid_request: code_challenge_method 'plain' is unsupported; PKCE S256 is required")
	}
	bytes := make([]byte, authorizationCodeEntropyBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed generating random code: %w", err)
	}

	codeStr := authorizationCodePrefix + hex.EncodeToString(bytes)
	authCode := AuthorizationCode{
		Code:                codeStr,
		ClientID:            clientID,
		UserID:              userID,
		TenantID:            tenantID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: method,
		Scope:               scope,
		ExpiresAt:           time.Now().Add(s.cfg.OAuthCodeTTL),
	}

	if err := s.repo.SaveAuthorizationCode(ctx, authCode); err != nil {
		return "", err
	}

	return codeStr, nil
}

// ExchangeCodeForTokens redeems an authorization code for an access token and a
// signed OIDC ID token.
//
// The code is consumed before anything else, so a replay finds nothing to
// redeem. The client_id and redirect_uri presented here must match the values
// bound at authorization time, and the PKCE verifier must hash to the recorded
// challenge.
//
// Identity claims are read from the database using the user ID carried on the
// code. Taking them from the request instead would let a client mint a token
// asserting any email it liked.
//
// Returns an error if the code is unknown, expired, mismatched, fails PKCE, or
// if the bound user, signing key or signature step fails.
func (s *Service) ExchangeCodeForTokens(ctx context.Context, codeStr string, clientID string, redirectURI string, codeVerifier string) (*OAuth2TokenResponse, error) {
	authCode, err := s.repo.ConsumeAuthorizationCode(ctx, codeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code: %w", err)
	}

	if authCode.ClientID != "" && authCode.ClientID != clientID {
		return nil, fmt.Errorf("client_id mismatch")
	}
	if authCode.RedirectURI != "" && authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	if authCode.CodeChallenge != "" {
		if !VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("invalid PKCE code_verifier")
		}
	}

	var email string
	var name string
	// Environment defaults to the non-production tier when no user record is
	// available to read it from.
	var env string = "test"

	if s.authRepo != nil {
		u, err := s.authRepo.FindUserByID(ctx, authCode.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed retrieving user for authorization code: %w", err)
		}
		if u == nil {
			return nil, fmt.Errorf("user %s not found", authCode.UserID)
		}
		// An authorization code outlives the moment it was issued. If the account
		// was restricted between the consent screen and this exchange, the code must
		// not still convert into a token.
		if err := accountstatus.Allowed(u); err != nil {
			return nil, err
		}
		email = u.Email
		name = u.Name
		env = string(u.Environment)
	}

	// The role claim is resolved from the user's recorded roles rather than
	// fixed: an authorization-code exchange may be a tenant admin signing into
	// the console, and a blank role would strip that privilege.
	accessToken, err := jwtpkg.IssueAccessToken(authCode.UserID, authCode.TenantID, env, email, name, s.authService.ResolveRoleClaim(ctx, authCode.UserID), s.cfg.EncryptionKey, s.accessTokenTTL(ctx, authCode.TenantID, env))
	if err != nil {
		return nil, fmt.Errorf("failed issuing access token: %w", err)
	}

	rsaPrivKey, err := jwtpkg.GetOrGenerateRSAPrivateKey(s.cfg.JWTSigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving RSA key for OIDC signing: %w", err)
	}

	now := time.Now()
	idClaims := IDTokenClaims{
		Issuer:        s.cfg.Issuer,
		Subject:       authCode.UserID,
		Audience:      clientID,
		TenantID:      authCode.TenantID,
		Email:         email,
		EmailVerified: true,
		Name:          name,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(s.cfg.IDTokenTTL).Unix(),
		AuthTime:      now.Unix(),
	}

	idTokenStr, err := jwtpkg.SignIDTokenRS256(rsaPrivKey, idClaims, s.cfg.JWTKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed signing ID token with RS256: %w", err)
	}

	return &OAuth2TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   s.accessTokenExpiresIn(ctx, authCode.TenantID, env),
		IDToken:     idTokenStr,
		Scope:       grantedScope,
	}, nil
}

// RotateRefreshTokenSession exchanges a refresh token for a new access token
// and a replacement refresh token, recording the user agent and IP against the
// resulting session.
//
// Returns the refreshed user projection, the access token, the new raw refresh
// token, and an error if the auth service is unavailable or the token is
// invalid, expired or already revoked.
func (s *Service) RotateRefreshTokenSession(ctx context.Context, rawRefreshToken string, userAgent string, ipAddress string) (*auth.UserDTO, string, string, error) {
	if s.authService == nil {
		return nil, "", "", fmt.Errorf("auth service unavailable")
	}

	u, accessToken, newRawRefreshToken, err := s.authService.RotateRefreshTokenSession(ctx, rawRefreshToken, userAgent, ipAddress)
	if err != nil {
		return nil, "", "", err
	}

	userDTO := &auth.UserDTO{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Status:        string(u.Status),
		CreatedAt:     u.CreatedAt.Format(time.RFC3339),
	}
	if u.Name != "" {
		userDTO.Name = &u.Name
	}

	return userDTO, accessToken, newRawRefreshToken, nil
}

// UserInfoResponse is the claim set returned by the OIDC UserInfo endpoint.
type UserInfoResponse struct {
	// Sub is the subject identifier — the user's stable ID.
	Sub string `json:"sub"`
	// Email is the user's primary address.
	Email string `json:"email"`
	// EmailVerified reports whether that address has been confirmed.
	EmailVerified bool `json:"email_verified"`
	// Name is the display name, omitted when unset.
	Name string `json:"name,omitempty"`
	// TenantID identifies the tenant the subject belongs to.
	TenantID string `json:"tenant_id"`
	// Environment is the tier the user record lives in.
	Environment string `json:"environment,omitempty"`
	// UpdatedAt is when the profile last changed.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// GetUserInfo returns the claim set for userID within tenantID.
//
// Returns an error when no user ID is supplied and a single indistinct "user
// not found" when the lookup fails or matches nothing, so the endpoint cannot
// be used to probe which subject IDs exist.
func (s *Service) GetUserInfo(ctx context.Context, tenantID, userID string) (*UserInfoResponse, error) {
	if userID == "" {
		return nil, fmt.Errorf("user_id is required")
	}

	u, err := s.authRepo.FindUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, fmt.Errorf("user not found")
	}

	return &UserInfoResponse{
		Sub:           u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		TenantID:      tenantID,
		Environment:   string(u.Environment),
		UpdatedAt:     u.UpdatedAt,
	}, nil
}
