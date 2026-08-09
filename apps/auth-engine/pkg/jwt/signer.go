/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/jwt/signer.go
 * Tier: Shared Package / Access Token Signing
 *
 * HS256-signed access tokens and MFA challenge tokens, plus the verifiers that
 * accept them back.
 *
 * These tokens are symmetric: the engine both signs and verifies them with the
 * same secret, and nothing outside the engine is expected to validate one. That
 * is why HS256 is sufficient here, while the OIDC ID tokens that relying
 * parties verify independently are RS256-signed and published through JWKS —
 * see rsa.go and key_manager.go.
 *
 * A token is a bearer credential: anyone holding one is treated as the subject
 * until it expires. Lifetimes are therefore short, and nothing that is not
 * already visible to the token's own bearer belongs in the claims, since the
 * payload is signed but not encrypted and decodes with base64 alone.
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

const (
	// tokenIssuer is the `iss` claim stamped on every token this file signs.
	tokenIssuer = "authn-engine"

	// accessTokenTTL bounds how long a leaked access token stays useful. Short
	// enough that a token lifted from a log or a proxy is stale before it can
	// be used at leisure; long enough that clients are not refreshing on nearly
	// every request. Revocation is not immediate — verification is offline and
	// consults no store — so this window is the actual exposure after a
	// session is revoked.
	accessTokenTTL = 15 * time.Minute

	// impersonationFallbackTTL applies when a caller requests an impersonation
	// token without stating a duration. Support access is deliberately not
	// open-ended.
	impersonationFallbackTTL = 15 * time.Minute

	// mfaChallengeTTL bounds the window between a correct password and a second
	// factor. It is far shorter than an access token's lifetime because the
	// challenge token represents a half-finished login: the password is already
	// proven, so anyone holding it needs only the second factor.
	mfaChallengeTTL = 5 * time.Minute

	// mfaChallengePurpose marks a token as usable only for completing a second
	// factor. VerifyMFAChallengeToken requires it, which is what stops a
	// challenge token from being replayed at an endpoint that expects a fully
	// authenticated access token.
	mfaChallengePurpose = "2fa_challenge"
)

// Claims is the access token payload.
//
// Everything here is readable by the bearer: the payload is base64, not
// encrypted, and the signature protects integrity only.
type Claims struct {
	// Sub is the authenticated user ID ("usr_...").
	Sub string `json:"sub"`
	// TenantID scopes the token to one tenant. Handlers must check it rather
	// than trusting a tenant identifier supplied in the request.
	TenantID string `json:"tenant_id"`
	// Environment is "test" or "live", keeping test-mode credentials from
	// acting on live data.
	Environment string `json:"environment"`
	// Email is the user's registered address at issue time.
	Email string `json:"email"`
	// Name is the user's display name, omitted when unset.
	Name string `json:"name,omitempty"`
	// Role is the platform role claim ("tenant_admin" for a tenant's first
	// user, empty for ordinary users).
	Role string `json:"role,omitempty"`
	// SessionID ties the token to a session record, so a revoked session can be
	// recognised by callers that do consult the session store.
	SessionID string `json:"sid,omitempty"`
	// ImpersonatorID is the administrator acting as this user, set only on
	// impersonation tokens. It is what makes an audit trail attribute actions
	// to the real operator rather than to the impersonated account.
	ImpersonatorID string `json:"impersonator_id,omitempty"`
	// IsImpersonated marks the token as an impersonation token so middleware
	// can refuse sensitive operations under it.
	IsImpersonated bool `json:"is_impersonated,omitempty"`
	// Iss identifies the issuing engine.
	Iss string `json:"iss"`
	// Iat is the issue time in Unix seconds.
	Iat int64 `json:"iat"`
	// Exp is the expiry in Unix seconds; verification rejects the token after it.
	Exp int64 `json:"exp"`
	// Jti is a per-token identifier derived from the issue timestamp in
	// nanoseconds. It distinguishes otherwise identical tokens in logs; it is
	// not random and is not a replay-prevention nonce.
	Jti string `json:"jti"`
}

// AccessTokenTTL returns the lifetime applied when a caller passes a
// non-positive ttl to either issuing function.
//
// It exists so a caller advertising `expires_in` can report the same number the
// token was actually signed with, rather than a second constant of its own.
func AccessTokenTTL() time.Duration {
	return accessTokenTTL
}

// resolveTTL returns ttl, or the built-in default when ttl is non-positive.
//
// A zero duration reaching here means the caller had no configured value; the
// alternative — signing a token that expires immediately — would take out every
// login rather than fail visibly.
func resolveTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return accessTokenTTL
	}
	return ttl
}

// IssueAccessToken signs an access token for a user, valid for ttl.
//
// role carries the platform role claim and may be empty for ordinary users.
// signingSecret is the engine's symmetric signing key. A non-positive ttl falls
// back to AccessTokenTTL.
//
// The lifetime is a parameter rather than a constant because the `expires_in`
// each caller advertises has to match the `exp` actually signed here; deriving
// them from two separate values let the API state a lifetime the token did not
// have.
//
// Returns an error only if the claims cannot be marshalled, which indicates a
// programming fault rather than a runtime condition.
func IssueAccessToken(userID string, tenantID string, environment string, email string, name string, role string, signingSecret string, ttl time.Duration) (string, error) {
	return IssueAccessTokenWithSession(userID, tenantID, environment, email, name, role, "", signingSecret, ttl)
}

// IssueAccessTokenWithSession signs an access token valid for ttl, carrying an
// explicit session ID in the `sid` claim so a consumer can correlate the token
// with a revocable session record.
//
// An empty sessionID omits the claim, which is what makes this the single
// implementation behind IssueAccessToken. A non-positive ttl falls back to
// AccessTokenTTL.
//
// Returns an error only if the claims cannot be marshalled.
func IssueAccessTokenWithSession(userID string, tenantID string, environment string, email string, name string, role string, sessionID string, signingSecret string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(resolveTTL(ttl))

	claims := Claims{
		Sub:         userID,
		TenantID:    tenantID,
		Environment: environment,
		Email:       email,
		Name:        name,
		Role:        role,
		SessionID:   sessionID,
		Iss:         tokenIssuer,
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

// IssueImpersonationToken signs an access token that identifies both the
// impersonated user and the administrator acting as them.
//
// A non-positive duration falls back to 15 minutes, so a caller that forgets to
// specify one cannot mint an unusually long-lived support session. The `jti`
// prefix distinguishes these tokens in logs.
//
// Returns an error only if the claims cannot be marshalled.
func IssueImpersonationToken(userID string, tenantID string, environment string, email string, name string, role string, impersonatorID string, durationMinutes time.Duration, signingSecret string) (string, error) {
	now := time.Now().UTC()
	if durationMinutes <= 0 {
		durationMinutes = impersonationFallbackTTL
	}
	exp := now.Add(durationMinutes)

	claims := Claims{
		Sub:            userID,
		TenantID:       tenantID,
		Environment:    environment,
		Email:          email,
		Name:           name,
		Role:           role,
		ImpersonatorID: impersonatorID,
		IsImpersonated: true,
		Iss:            tokenIssuer,
		Iat:            now.Unix(),
		Exp:            exp.Unix(),
		Jti:            fmt.Sprintf("jti_imp_%d", now.UnixNano()),
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed marshaling impersonation jwt claims: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := encodedHeader + "." + encodedPayload

	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return signingInput + "." + signature, nil
}

// VerifyAccessToken checks a token's signature and expiry and returns its claims.
//
// Distinct errors describe a malformed token, a bad signature, an undecodable
// payload and an expired token. All of them mean the same thing to a caller —
// reject the request — so handlers should map them to one generic response
// rather than reporting which check failed.
//
// Expiry is compared without leeway, so clock skew between instances can reject
// a token a moment before its peers would.
func VerifyAccessToken(tokenString string, signingSecret string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt format")
	}

	// The header's `alg` is deliberately never consulted. Recomputing HS256
	// unconditionally is what makes algorithm-confusion attacks inert: a token
	// rewritten to "alg":"none", or to RS256 so the public key is treated as an
	// HMAC secret, still has to carry a signature valid under this secret.
	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(signingInput))
	expectedSignature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Constant-time comparison. A byte-wise comparison that stops at the first
	// difference takes measurably longer the more leading bytes are correct,
	// which lets an attacker who can time repeated requests build a valid
	// signature one byte at a time.
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
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

// MFAClaims is the payload of the short-lived token issued between a successful
// password check and second-factor entry.
type MFAClaims struct {
	// Sub is the user ID part-way through logging in.
	Sub string `json:"sub"`
	// TenantID scopes the challenge to one tenant.
	TenantID string `json:"tenant_id"`
	// Environment is "test" or "live".
	Environment string `json:"environment"`
	// Methods lists the second factors this user may complete, so the client
	// can present the right prompt without a further round trip.
	Methods []string `json:"methods"`
	// Purpose is always mfaChallengePurpose and is checked on verification,
	// preventing this token from being presented as an access token.
	Purpose string `json:"purpose"`
	// Iss identifies the issuing engine.
	Iss string `json:"iss"`
	// Iat is the issue time in Unix seconds.
	Iat int64 `json:"iat"`
	// Exp is the expiry in Unix seconds.
	Exp int64 `json:"exp"`
}

// IssueMFAChallengeToken signs a 5-minute token proving the password step
// succeeded, to be presented alongside the second factor.
//
// methods tells the client which factors are enrolled. Listing them is not a
// disclosure: the caller has already proven the password.
//
// Returns an error only if the claims cannot be marshalled.
func IssueMFAChallengeToken(userID string, tenantID string, environment string, methods []string, signingSecret string) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(mfaChallengeTTL)

	claims := MFAClaims{
		Sub:         userID,
		TenantID:    tenantID,
		Environment: environment,
		Methods:     methods,
		Purpose:     mfaChallengePurpose,
		Iss:         tokenIssuer,
		Iat:         now.Unix(),
		Exp:         exp.Unix(),
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed marshaling mfa claims: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := encodedHeader + "." + encodedPayload

	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return signingInput + "." + signature, nil
}

// VerifyMFAChallengeToken checks an MFA challenge token and returns its claims.
//
// Beyond signature and expiry it requires the purpose claim, which is what
// keeps a challenge token — issued before the second factor was supplied — from
// being accepted anywhere a fully authenticated token is expected.
//
// Every failure mode means "restart the login"; callers should not distinguish
// them to the client.
func VerifyMFAChallengeToken(tokenString string, signingSecret string) (*MFAClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid mfa token format")
	}

	// As with access tokens, the header's `alg` is ignored and HS256 is
	// recomputed unconditionally.
	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(signingSecret))
	h.Write([]byte(signingInput))
	expectedSignature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Constant-time comparison, for the same reason as VerifyAccessToken.
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid mfa token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed decoding mfa token payload: %w", err)
	}

	var claims MFAClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed unmarshaling mfa token claims: %w", err)
	}

	if claims.Purpose != mfaChallengePurpose {
		return nil, fmt.Errorf("invalid mfa token purpose")
	}

	if time.Now().UTC().Unix() > claims.Exp {
		return nil, fmt.Errorf("mfa challenge token has expired")
	}

	return &claims, nil
}
