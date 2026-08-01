/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/services/auth_service.go
 * Tier: Domain Logic / Service Layer
 *
 * Description: Core authentication service handling password hashing via RFC 9106 Argon2id,
 *              peppered HMAC API key verification, session creation, SHA-256 refresh token
 *              rotation with 10-second grace window, and anomaly revocation.
 *
 * Security Notice:
 *   - Passwords must be hashed using Argon2id (t=3, m=64MB, p=4).
 *   - Refresh tokens are stored strictly as SHA-256 hashes.
 *   - Replaying a revoked refresh token triggers immediate revocation of ALL user sessions.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package services

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
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/repository"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserAlreadyExists  = errors.New("user with this email already exists")
	ErrInvalidApiKey      = errors.New("invalid or expired api key")
	ErrInvalidToken       = errors.New("invalid or revoked refresh token")
	ErrAccountFrozen      = errors.New("account is on 48-hour recovery hold")
	ErrAccountBanned      = errors.New("account has been banned")
)

// AuthService encapsulates domain business logic for core authentication flows.
type AuthService struct {
	repo   *repository.AuthRepository
	config *config.EnvConfig
}

// NewAuthService constructs a new AuthService instance.
//
// Parameters:
//   - repo: AuthRepository data access instance.
//   - cfg: Validated EnvConfig instance.
//
// Returns:
//   - *AuthService: Initialized service instance.
func NewAuthService(repo *repository.AuthRepository, cfg *config.EnvConfig) *AuthService {
	return &AuthService{
		repo:   repo,
		config: cfg,
	}
}

// HashPassword generates an RFC 9106 Argon2id password hash ($t=3, m=64MB, p=4$).
//
// Parameters:
//   - password: Plain text password string.
//
// Returns:
//   - string: Formatted Argon2id hash string containing salt and parameters.
//   - error: Non-nil if random salt generation fails.
func (s *AuthService) HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed generating random salt: %w", err)
	}

	// RFC 9106 Argon2id baseline: t=3 iterations, m=64MB (65536 KB), p=4 threads
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	encoded := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(hash),
	)
	return encoded, nil
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
func (s *AuthService) ValidateApiKey(ctx context.Context, rawKey string) (*ent.ApiKey, error) {
	if rawKey == "" {
		return nil, ErrInvalidApiKey
	}

	// Compute peppered HMAC-SHA256 hash of the presented key
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
func (s *AuthService) SignUpWithPassword(ctx context.Context, tenantID string, env string, email string, password string, name string) (*ent.User, string, error) {
	existing, err := s.repo.FindUserByEmail(ctx, tenantID, env, email)
	if err != nil {
		return nil, "", err
	}
	if existing != nil {
		return nil, "", ErrUserAlreadyExists
	}

	passwordHash, err := s.HashPassword(password)
	if err != nil {
		return nil, "", err
	}

	userID := fmt.Sprintf("usr_%s", uuid.New().String()[:12])
	u, err := s.repo.CreateUser(ctx, userID, tenantID, env, email, passwordHash, name)
	if err != nil {
		return nil, "", err
	}

	// Generate raw 64-byte opaque refresh token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("failed generating refresh token: %w", err)
	}
	rawRefreshToken := hex.EncodeToString(tokenBytes)

	// Compute SHA-256 hash for database storage
	h := sha256.Sum256([]byte(rawRefreshToken))
	tokenHash := hex.EncodeToString(h[:])

	sessionID := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30-day session TTL
	_, err = s.repo.CreateSession(ctx, sessionID, u.ID, tokenHash, "", "", expiresAt)
	if err != nil {
		return nil, "", err
	}

	return u, rawRefreshToken, nil
}
