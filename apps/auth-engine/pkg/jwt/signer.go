/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/signer.go
 * Tier: Shared Package / JWT Token Signer
 *
 * Description: RS256 / HS256 JWT access token signer and claim validator.
 *              Issues 15-minute access tokens for client authentication.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Claims represents the standard JWT access token payload structure.
type Claims struct {
	Sub         string `json:"sub"`
	TenantID    string `json:"tenant_id"`
	Environment string `json:"environment"`
	Email       string `json:"email"`
	Name        string `json:"name,omitempty"`
	Iss         string `json:"iss"`
	Iat         int64  `json:"iat"`
	Exp         int64  `json:"exp"`
	Jti         string `json:"jti"`
}

// IssueAccessToken creates and signs a 15-minute JWT access token string.
//
// Parameters:
//   - userID: User ID (`usr_...`).
//   - tenantID: Tenant ID scope.
//   - environment: "test" or "live".
//   - email: User registered email.
//   - name: User name.
//   - signingSecret: Signing secret key string (`AUTHN_ENCRYPTION_KEY`).
//
// Returns:
//   - string: Signed JWT string (`header.payload.signature`).
//   - error: Non-nil if signing fails.
func IssueAccessToken(userID string, tenantID string, environment string, email string, name string, signingSecret string) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(15 * time.Minute) // 15-minute Access Token TTL

	claims := Claims{
		Sub:         userID,
		TenantID:    tenantID,
		Environment: environment,
		Email:       email,
		Name:        name,
		Iss:         "authn-engine",
		Iat:         now.Unix(),
		Exp:         exp.Unix(),
		Jti:         fmt.Sprintf("jti_%d", now.UnixNano()),
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed marshaling jwt claims: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := encodedHeader + "." + encodedPayload

	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return signingInput + "." + signature, nil
}

// VerifyAccessToken verifies signature and expiration of a JWT access token string.
//
// Parameters:
//   - tokenString: Raw JWT token string.
//   - signingSecret: Signing secret key string.
//
// Returns:
//   - *Claims: Parsed JWT claims if valid.
//   - error: Non-nil if token is invalid or expired.
func VerifyAccessToken(tokenString string, signingSecret string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt format")
	}

	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(signingInput))
	expectedSignature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if parts[2] != expectedSignature {
		return nil, fmt.Errorf("invalid jwt signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed decoding jwt payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed unmarshaling jwt claims: %w", err)
	}

	if time.Now().UTC().Unix() > claims.Exp {
		return nil, fmt.Errorf("jwt access token has expired")
	}

	return &claims, nil
}
