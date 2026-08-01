/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/service.go
 * Tier: Internal Feature Package / Auth Service
 *
 * Description: Core authentication domain logic handling signup, login, session issuance,
 *              API key validation, and password security.
 *
 * Security Notice:
 *   - Passwords must be hashed using Argon2id (t=3, m=64MB, p=4).
 *   - Refresh tokens are stored strictly as SHA-256 hashes.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserAlreadyExists  = errors.New("user with this email already exists")
	ErrInvalidApiKey      = errors.New("invalid or expired api key")
	ErrInvalidToken       = errors.New("invalid or revoked refresh token")
)

// Service handles domain business logic for authentication.
type Service struct {
	repo   *Repository
	config *config.EnvConfig
}

// NewService constructs a new Service instance.
//
// Parameters:
//   - repo: Feature Repository instance.
//   - cfg: Validated EnvConfig instance.
//
// Returns:
//   - *Service: Initialized service instance.
func NewService(repo *Repository, cfg *config.EnvConfig) *Service {
	return &Service{
		repo:   repo,
		config: cfg,
	}
}

// ValidateApiKey checks a publishable (pk_...) or secret (sk_...) API key against database hashes.
//
// Parameters:
//   - ctx: Request context.
//   - rawKey: Raw API key header string.
//
// Returns:
//   - *ent.ApiKey: Validated API key entity.
//   - error: ErrInvalidApiKey if key is invalid or revoked.
func (s *Service) ValidateApiKey(ctx context.Context, rawKey string) (*ent.ApiKey, error) {
	if rawKey == "" {
		return nil, ErrInvalidApiKey
	}

	h := hmac.New(sha256.New, []byte(s.config.AuthnAPIKeyPepper))
	h.Write([]byte(rawKey))
	keyHash := hex.EncodeToString(h.Sum(nil))

	key, err := s.repo.FindApiKeyByHash(ctx, keyHash)
	if err != nil || key == nil {
		return nil, ErrInvalidApiKey
	}

	if key.RevokedAt != nil {
		return nil, ErrInvalidApiKey
	}
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, ErrInvalidApiKey
	}

	return key, nil
}

// SignUpWithPassword registers a new user with password credentials.
//
// Parameters:
//   - ctx: Request context.
//   - tenantID: Tenant ID scope.
//   - env: Environment mode ("test" or "live").
//   - email: User registered email address.
//   - password: Plain text password string.
//   - name: Optional full name string.
//
// Returns:
//   - *ent.User: Created user entity.
//   - string: Raw 64-byte opaque refresh token string.
//   - error: ErrUserAlreadyExists or creation error.
func (s *Service) SignUpWithPassword(ctx context.Context, tenantID string, env string, email string, password string, name string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	if err := s.repo.EnsureTenantExists(ctx, tenantID); err != nil {
		return nil, "", "", err
	}

	existing, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)
	if err != nil {
		return nil, "", "", err
	}
	if existing != nil {
		return nil, "", "", ErrUserAlreadyExists
	}

	passwordHash, err := crypto.HashPasswordArgon2id(password)
	if err != nil {
		return nil, "", "", err
	}

	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	u, err := s.repo.CreateUser(ctx, userID, tenantID, env, email, passwordHash, name)
	if err != nil {
		return nil, "", "", err
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", "", fmt.Errorf("failed generating refresh token: %w", err)
	}
	rawRefreshToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_, err = s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt)
	if err != nil {
		return nil, "", "", err
	}

	// Issue 15-minute JWT Access Token
	accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	// Audit Log recording
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, tenantID, u.ID, "user.signed_up", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}

// ValidatePasswordCredentials checks password credentials and issues a login session.
func (s *Service) ValidatePasswordCredentials(ctx context.Context, tenantID string, env string, email string, password string, userAgent string, ipAddress string) (*ent.User, string, string, error) {
	u, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)
	if err != nil || u == nil {
		return nil, "", "", ErrInvalidCredentials
	}

	if u.PasswordHash == "" || !crypto.VerifyPasswordArgon2id(password, u.PasswordHash) {
		return nil, "", "", ErrInvalidCredentials
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", "", fmt.Errorf("failed generating refresh token: %w", err)
	}
	rawRefreshToken := hex.EncodeToString(tokenBytes)

	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_, err = s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, userAgent, ipAddress, expiresAt)
	if err != nil {
		return nil, "", "", err
	}

	// Issue 15-minute JWT Access Token
	accessToken, err := jwt.IssueAccessToken(u.ID, tenantID, env, u.Email, u.Name, s.config.AuthnEncryptionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed issuing access token: %w", err)
	}

	// Update last sign in & Audit Log
	_ = s.repo.UpdateUserLastSignIn(ctx, u.ID)
	auditID := fmt.Sprintf("aud_%s", uuid.New().String()[:12])
	_ = s.repo.CreateAuditLog(ctx, auditID, tenantID, u.ID, "user.signed_in", ipAddress, userAgent, "")

	return u, accessToken, rawRefreshToken, nil
}
