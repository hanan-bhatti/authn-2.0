/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/session/service.go
 * Tier: Session Management Layer
 *
 * Description: Orchestration layer for session management — handles refresh token
 *              rotation, 10-second grace window, reuse detection & automatic compromise
 *              mitigation, active session listing, and session revocation.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	jwtpkg "github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

// Service handles domain logic for session management.
type Service struct {
	repo *Repository
	cfg  *config.EnvConfig
}

// NewService constructs a new Session Service.
func NewService(repo *Repository, cfg *config.EnvConfig) *Service {
	return &Service{repo: repo, cfg: cfg}
}

// SessionResponse represents a normalized session object returned to clients.
type SessionResponse struct {
	ID           string     `json:"id"`
	Device       DeviceInfo `json:"device"`
	IPAddress    string     `json:"ip_address"`
	Location     string     `json:"location"`
	LastActiveAt string     `json:"last_active_at,omitempty"`
	CreatedAt    string     `json:"created_at"`
	IsCurrent    bool       `json:"is_current"`
}

// SessionTokenPairResponse represents the output of a token refresh or creation.
type SessionTokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	SessionID    string `json:"session_id"`
}

// RotateRefreshToken exchanges an old refresh token for a new access & refresh token pair.
// Enforces 10-second grace window for concurrent requests, and revokes all user sessions
// if token reuse is detected outside the grace period.
func (s *Service) RotateRefreshToken(ctx context.Context, tenantID, environment, rawRefreshToken, clientIP, userAgent string) (*SessionTokenPairResponse, error) {
	if rawRefreshToken == "" {
		return nil, errors.New("refresh_token is required")
	}

	hash := HashRefreshToken(rawRefreshToken)
	sess, err := s.repo.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	// Helper to enforce tenant-level TokenReusePolicy on compromise detection
	revokeOnCompromise := func(tID, uID, sID string) {
		if s.repo.Factory() != nil && tID != "" {
			policyRepo := policy.NewRepository(s.repo.Factory())
			secPol, err := policyRepo.GetSecurityPolicy(ctx, tID)
			if err == nil && secPol.TokenReusePolicy == "session_revoke" {
				_ = s.repo.RevokeSession(ctx, sID)
				return
			}
		}
		_, _ = s.repo.RevokeAllUserSessions(ctx, uID, "")
	}

	// Case 1: Session is already revoked
	if sess.Status == session.StatusRevoked {
		// REUSE DETECTED! Apply tenant TokenReusePolicy (global_revoke vs session_revoke)
		revokeOnCompromise(tenantID, sess.UserID, sess.ID)
		return nil, ErrSessionCompromised
	}

	// Case 2: Session was rotated into grace window
	if sess.Status == session.StatusRotatedGrace {
		if sess.GraceExpiresAt != nil && time.Now().After(*sess.GraceExpiresAt) {
			// Grace period EXPIRED -> REUSE DETECTED!
			revokeOnCompromise(tenantID, sess.UserID, sess.ID)
			return nil, ErrSessionCompromised
		}

		// Grace period ACTIVE -> return the token generated during rotation
		if sess.SupersededBySessionID != nil {
			supersededSess, err := s.repo.GetSessionByID(ctx, *sess.SupersededBySessionID)
			if err == nil && supersededSess.Status == session.StatusActive {
				userObj, err := s.getUserByID(ctx, supersededSess.UserID)
				if err != nil {
					return nil, fmt.Errorf("failed to load session user: %w", err)
				}

				accessToken, err := jwtpkg.IssueAccessToken(userObj.ID, tenantID, environment, userObj.Email, userObj.Name, "", s.cfg.AuthnEncryptionKey)
				if err != nil {
					return nil, fmt.Errorf("failed to issue access token: %w", err)
				}

				return &SessionTokenPairResponse{
					AccessToken:  accessToken,
					RefreshToken: "", // Do not re-expose new refresh token in grace period response
					TokenType:    "Bearer",
					ExpiresIn:    900,
					SessionID:    supersededSess.ID,
				}, nil
			}
		}
	}

	// Case 3: Session is active -> check expiration
	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Fetch user details for access token claims
	userObj, err := s.getUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}

	// Rotate session: old session -> rotated_grace (10s window), new session -> active (30d TTL)
	graceSeconds := 10
	ttlDays := 30
	newSess, newRawToken, err := s.repo.RotateSession(ctx, tenantID, environment, sess.ID, "", graceSeconds, ttlDays)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate session: %w", err)
	}

	// Issue new Access Token JWT
	accessToken, err := jwtpkg.IssueAccessToken(userObj.ID, tenantID, environment, userObj.Email, userObj.Name, "", s.cfg.AuthnEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to issue access token: %w", err)
	}

	return &SessionTokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: newRawToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
		SessionID:    newSess.ID,
	}, nil
}

// ListUserSessions returns all active sessions for a user, marking currentSessionID.
func (s *Service) ListUserSessions(ctx context.Context, userID, currentSessionID string) ([]SessionResponse, error) {
	if userID == "" {
		return nil, errors.New("user_id is required")
	}

	sessions, err := s.repo.GetUserActiveSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query active sessions: %w", err)
	}

	resp := make([]SessionResponse, 0, len(sessions))
	for _, sess := range sessions {
		lastActive := ""
		if sess.LastActiveAt != nil {
			lastActive = sess.LastActiveAt.Format(time.RFC3339)
		}

		resp = append(resp, SessionResponse{
			ID:           sess.ID,
			Device:       ParseUserAgent(sess.UserAgent),
			IPAddress:    sess.IPAddress,
			Location:     sess.Location,
			LastActiveAt: lastActive,
			CreatedAt:    sess.CreatedAt.Format(time.RFC3339),
			IsCurrent:    sess.ID == currentSessionID,
		})
	}

	return resp, nil
}

// RevokeSession revokes a specific session belonging to userID.
func (s *Service) RevokeSession(ctx context.Context, userID, targetSessionID string) error {
	if userID == "" || targetSessionID == "" {
		return errors.New("user_id and session_id are required")
	}

	sess, err := s.repo.GetSessionByID(ctx, targetSessionID)
	if err != nil {
		return ErrSessionNotFound
	}

	if sess.UserID != userID {
		return errors.New("unauthorized: session does not belong to user")
	}

	return s.repo.RevokeSession(ctx, targetSessionID)
}

// RevokeOtherSessions revokes all sessions for userID except currentSessionID.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID, currentSessionID string) (int, error) {
	if userID == "" {
		return 0, errors.New("user_id is required")
	}
	return s.repo.RevokeAllUserSessions(ctx, userID, currentSessionID)
}

// RevokeAllSessions revokes all sessions for userID.
func (s *Service) RevokeAllSessions(ctx context.Context, userID string) (int, error) {
	if userID == "" {
		return 0, errors.New("user_id is required")
	}
	return s.repo.RevokeAllUserSessions(ctx, userID, "")
}

// getUserByID is a internal helper to load user record via ent client factory.
func (s *Service) getUserByID(ctx context.Context, userID string) (*ent.User, error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}
