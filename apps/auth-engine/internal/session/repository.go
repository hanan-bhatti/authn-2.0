// Copyright (c) 2026 Hanan Bhatti
// This file is part of Authn.
//
// Authn is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Authn is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Authn.  If not, see <https://www.gnu.org/licenses/>.

package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

var (
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionRevoked     = errors.New("session has been revoked")
	ErrSessionExpired     = errors.New("session has expired")
	ErrSessionCompromised = errors.New("session reuse detected; all sessions revoked for security")
	// ErrSessionNotOwned is returned when a caller tries to act on a session
	// belonging to another user. Previously this was an anonymous errors.New in
	// the service, so the handler had to match on error text to pick its status.
	ErrSessionNotOwned = errors.New("unauthorized: session does not belong to user")
)

type Repository struct {
	factory *clientfactory.ClientFactory
}

func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

func (r *Repository) Factory() *clientfactory.ClientFactory {
	return r.factory
}

// HashRefreshToken returns the SHA-256 hex digest of a raw 64-byte opaque refresh token.
func HashRefreshToken(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

func (r *Repository) CreateSession(ctx context.Context, tenantID, environment, userID, rawRefreshToken, ipAddress, userAgent, deviceFingerprintHmac, location string, ttlDays int) (*ent.Session, string, error) {
	rawToken := rawRefreshToken
	if rawToken == "" {
		rawToken = uuid.New().String() + uuid.New().String()
	}
	hash := HashRefreshToken(rawToken)
	id := fmt.Sprintf("ses_%s", uuid.New().String()[:12])
	now := time.Now()
	expiresAt := now.Add(time.Duration(ttlDays) * 24 * time.Hour)

	sess, err := r.factory.GetClient(ctx, tenantID, environment).Session.Create().
		SetID(id).
		SetUserID(userID).
		SetRefreshTokenHash(hash).
		SetStatus(session.StatusActive).
		SetIPAddress(ipAddress).
		SetUserAgent(userAgent).
		SetDeviceFingerprintHmac(deviceFingerprintHmac).
		SetLocation(location).
		SetLastActiveAt(now).
		SetExpiresAt(expiresAt).
		Save(ctx)
	if err != nil {
		return nil, "", err
	}

	return sess, rawToken, nil
}

func (r *Repository) GetSessionByTokenHash(ctx context.Context, hash string) (*ent.Session, error) {
	sess, err := r.factory.GetClient(ctx, "", "").Session.Query().
		Where(session.RefreshTokenHash(hash)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return sess, nil
}

func (r *Repository) GetSessionByID(ctx context.Context, sessionID string) (*ent.Session, error) {
	sess, err := r.factory.GetClient(ctx, "", "").Session.Get(ctx, sessionID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	return sess, nil
}

func (r *Repository) RotateSession(ctx context.Context, tenantID, environment, oldSessionID, newRawToken string, graceSeconds int, ttlDays int) (*ent.Session, string, error) {
	client := r.factory.GetClient(ctx, tenantID, environment)
	oldSess, err := client.Session.Get(ctx, oldSessionID)
	if err != nil {
		return nil, "", err
	}

	newSess, newRaw, err := r.CreateSession(ctx, tenantID, environment, oldSess.UserID, newRawToken, oldSess.IPAddress, oldSess.UserAgent, oldSess.DeviceFingerprintHmac, oldSess.Location, ttlDays)
	if err != nil {
		return nil, "", err
	}

	graceExpiresAt := time.Now().Add(time.Duration(graceSeconds) * time.Second)
	_, err = client.Session.UpdateOneID(oldSessionID).
		SetStatus(session.StatusRotatedGrace).
		SetGraceExpiresAt(graceExpiresAt).
		SetSupersededBySessionID(newSess.ID).
		Save(ctx)
	if err != nil {
		return nil, "", err
	}

	return newSess, newRaw, nil
}

func (r *Repository) RevokeSession(ctx context.Context, sessionID string) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.Session.UpdateOneID(sessionID).
		SetStatus(session.StatusRevoked).
		Exec(ctx)
}

func (r *Repository) RevokeAllUserSessions(ctx context.Context, userID string, exceptSessionID string) (int, error) {
	client := r.factory.GetClient(ctx, "", "")
	pred := session.UserID(userID)
	if exceptSessionID != "" {
		pred = session.And(pred, session.IDNEQ(exceptSessionID))
	}

	return client.Session.Update().
		Where(pred, session.StatusNEQ(session.StatusRevoked)).
		SetStatus(session.StatusRevoked).
		Save(ctx)
}

func (r *Repository) GetUserActiveSessions(ctx context.Context, userID string) ([]*ent.Session, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.Session.Query().
		Where(
			session.UserID(userID),
			session.StatusNEQ(session.StatusRevoked),
			session.ExpiresAtGT(time.Now()),
		).
		Order(ent.Desc(session.FieldLastActiveAt)).
		All(ctx)
}

func (r *Repository) TouchLastActive(ctx context.Context, sessionID string) error {
	client := r.factory.GetClient(ctx, "", "")
	now := time.Now()
	return client.Session.UpdateOneID(sessionID).
		SetLastActiveAt(now).
		Exec(ctx)
}
