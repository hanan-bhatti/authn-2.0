/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/user/service.go
 * Tier: Business Logic Layer / User Profile & Settings Service
 *
 * Description: Business logic for user self-service: profile updates, password changes,
 *              primary email change and recovery email registration (both confirmed by
 *              single-use emailed tokens), linked social account management, and account
 *              erasure with its dependent records.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package user

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/auth"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/webhook"
)

// Fallback lifetimes and origin, applied only when the service is constructed
// without a *config.Config. They reproduce the defaults config.Load gives
// EmailVerificationTTL, RecoveryTokenTTL and APP_BASE_URL.
const (
	// fallbackEmailChangeTokenTTL bounds how long a primary-email change link
	// works. Kept short because following it moves the address used to sign in.
	fallbackEmailChangeTokenTTL = 1 * time.Hour
	// fallbackRecoveryEmailTokenTTL bounds how long a recovery-email
	// confirmation link works. Longer than the primary-email window, since
	// confirming a secondary address grants no immediate access.
	fallbackRecoveryEmailTokenTTL = 24 * time.Hour
	// fallbackVerificationBaseURL is the origin prefixed to emailed links when
	// neither the calling application nor the deployment names one. It is the
	// account app's dev port, because an emailed link has to open a page.
	fallbackVerificationBaseURL = config.DefaultFrontendBaseURL
)

// Keys under which pending-verification state is held in a user's metadata bag.
// Writer and reader must agree exactly, so each key is named once here.
const (
	// metaPendingNewEmail holds the address awaiting confirmation.
	metaPendingNewEmail = "pending_new_email"
	// metaPendingEmailTokenHash holds the SHA-256 digest of the emailed token.
	metaPendingEmailTokenHash = "pending_email_token_hash"
	// metaPendingEmailExpiresAt holds that token's expiry, in Unix seconds.
	metaPendingEmailExpiresAt = "pending_email_expires_at"

	// metaRecoveryEmail holds the secondary recovery address.
	metaRecoveryEmail = "recovery_email"
	// metaRecoveryEmailVerified reports whether that address was confirmed.
	metaRecoveryEmailVerified = "recovery_email_verified"
	// metaRecoveryEmailTokenHash holds the SHA-256 digest of the emailed token.
	metaRecoveryEmailTokenHash = "recovery_email_token_hash"
	// metaRecoveryEmailExpiresAt holds that token's expiry, in Unix seconds.
	metaRecoveryEmailExpiresAt = "recovery_email_expires_at"
)

// Service implements the user self-service operations.
type Service struct {
	// authRepo provides the shared user store and ent client factory.
	authRepo *auth.Repository
	// emailProvider delivers verification mail. Nil disables delivery, which
	// leaves the token retrievable only from the service's return value.
	emailProvider email.EmailProvider
	// policyRepo supplies the tenant password policy. Nil skips policy checks.
	policyRepo *policy.Repository
	// webhookDispatcher publishes account lifecycle events. Nil disables them.
	webhookDispatcher *webhook.Dispatcher
	// cfg supplies token lifetimes and the public origin used to build emailed
	// links. Nil falls back to the constants above.
	cfg *config.Config
	// frontendURLs supplies the calling application's own UI origin for emailed
	// links. Nil gives every application the deployment default; see
	// verificationBaseURL.
	frontendURLs FrontendURLResolver
}

// FrontendURLResolver supplies the origin an application's emailed links point at.
//
// Declared here rather than imported so this package does not depend on the
// settings cache and a test can fix an origin without a database.
// settings.Resolver satisfies it, as does auth.FrontendURLResolver's
// implementation — they are the same method.
//
// It does not fail: "" means the application configured none, so a lookup problem
// downgrades a link to the deployment default rather than failing the send.
type FrontendURLResolver interface {
	// FrontendBaseURL returns the application's configured origin, or "" when it
	// has none.
	FrontendBaseURL(ctx context.Context, applicationID string) string
}

// NewService constructs a user Service. emailProvider, policyRepo and
// webhookDispatcher are each optional and may be nil.
//
// cfg is variadic only so existing callers keep compiling; pass it in
// application code. Without it, emailed verification links point at the local
// development origin rather than the deployment's own address.
func NewService(authRepo *auth.Repository, emailProvider email.EmailProvider, policyRepo *policy.Repository, webhookDispatcher *webhook.Dispatcher, cfg ...*config.Config) *Service {
	s := &Service{
		authRepo:          authRepo,
		emailProvider:     emailProvider,
		policyRepo:        policyRepo,
		webhookDispatcher: webhookDispatcher,
	}
	if len(cfg) > 0 {
		s.cfg = cfg[0]
	}
	return s
}

// WithFrontendURLResolver points emailed links at the calling application's own
// UI origin and returns the service for chaining.
//
// Optional: a test building this service wants the deployment default rather than
// a settings cache.
func (s *Service) WithFrontendURLResolver(r FrontendURLResolver) *Service {
	s.frontendURLs = r
	return s
}

// emailChangeTokenTTL returns how long a primary-email change link stays valid.
func (s *Service) emailChangeTokenTTL() time.Duration {
	if s.cfg != nil && s.cfg.EmailVerificationTTL > 0 {
		return s.cfg.EmailVerificationTTL
	}
	return fallbackEmailChangeTokenTTL
}

// recoveryEmailTokenTTL returns how long a recovery-email confirmation link
// stays valid.
func (s *Service) recoveryEmailTokenTTL() time.Duration {
	if s.cfg != nil && s.cfg.RecoveryTokenTTL > 0 {
		return s.cfg.RecoveryTokenTTL
	}
	return fallbackRecoveryEmailTokenTTL
}

// verificationBaseURL returns the origin prefixed to emailed verification
// links, with no trailing slash.
//
// It must be the address a recipient's browser can actually reach, and it must be
// a page rather than an API route: the click carries no publishable-key header,
// so the landing page makes the call with the key it already holds.
//
// Precedence is the calling application's configured origin, then the
// deployment's, then the local development default. The application comes first
// because one tenant may run several applications on separate domains.
//
// The application is read from the privacy context, never from a request field. A
// publishable key ships in browser bundles, so a caller-supplied origin would let
// anyone holding one have the engine mail a live confirmation token to a domain
// they control.
func (s *Service) verificationBaseURL(ctx context.Context) string {
	if s.frontendURLs != nil {
		if p, ok := privacy.FromContext(ctx); ok && p.ApplicationID != "" {
			if configured := strings.TrimSpace(s.frontendURLs.FrontendBaseURL(ctx, p.ApplicationID)); configured != "" {
				return strings.TrimRight(configured, "/")
			}
		}
	}
	if s.cfg != nil && s.cfg.FrontendBaseURL != "" {
		return strings.TrimRight(s.cfg.FrontendBaseURL, "/")
	}
	return fallbackVerificationBaseURL
}

// newVerificationToken returns a random single-use token carrying the given
// prefix, together with the SHA-256 digest to store in its place.
//
// Only the digest is persisted, so reading the database yields no usable token.
func newVerificationToken(prefix string) (token, tokenHash string, err error) {
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed generating random token: %w", err)
	}
	token = prefix + hex.EncodeToString(tokenBytes)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// hashVerificationToken returns the stored digest form of a presented token.
func hashVerificationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// metadataUnixTime reads a Unix-seconds timestamp out of a metadata bag.
//
// Metadata makes a JSON round trip through the database, so a value written as
// int64 comes back as float64; both are accepted. ok is false when the key is
// absent or holds something non-numeric, which callers must treat as a failure
// rather than as "no expiry".
func metadataUnixTime(meta map[string]interface{}, key string) (time.Time, bool) {
	switch v := meta[key].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case int:
		return time.Unix(int64(v), 0), true
	default:
		return time.Time{}, false
	}
}
