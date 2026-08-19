/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/impersonation/service.go
 * Tier: Internal Feature Package / Impersonation Service
 *
 * Admin user impersonation (FR-14).
 *
 * Impersonation lets a support agent act as a user in order to see what that
 * user sees. Every guard in this file exists because the operation is a
 * deliberate, audited breach of the usual identity boundary: the caller must
 * hold the permission, the target must be impersonatable under tenant policy,
 * the session is capped by that policy rather than by the request, and both the
 * webhook stream and the user's own inbox are told it happened.
 *
 * The token issued here is marked impersonated, which the read-only guard in
 * internal/middleware reads to refuse destructive mutations for its lifetime.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package impersonation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

var (
	// ErrImpersonationDisabled reports that tenant policy has the feature off.
	ErrImpersonationDisabled = errors.New("impersonation feature is disabled for this tenant")
	// ErrUserNotFound reports that the target user does not exist in the tenant.
	ErrUserNotFound = errors.New("target user not found")
	// ErrUserNotActive reports a target whose account is suspended or otherwise
	// not in the active state.
	ErrUserNotActive = errors.New("cannot impersonate suspended or unverified user")
	// ErrCannotImpersonateSelf reports that caller and target are the same user.
	ErrCannotImpersonateSelf = errors.New("cannot impersonate self")
	// ErrCannotImpersonateAdmin reports a target holding an administrative role
	// while tenant policy restricts admin impersonation.
	ErrCannotImpersonateAdmin = errors.New("cannot impersonate admin users")
	// ErrUserOptInRequired reports a target who has not enabled support access
	// while tenant policy requires it.
	ErrUserOptInRequired = errors.New("target user has not granted support access permission")
	// ErrInsufficientPermissions reports a caller without users:impersonate.
	ErrInsufficientPermissions = errors.New("caller lacks required 'users:impersonate' permission")
)

// adminRoleSlugs are the role slugs that make a user an administrator for the
// purpose of RestrictAdminImpersonation.
//
// This is intentionally broader than rbac's privileged-role set, which decides
// who may bypass a permission check. Here the question is who must be protected
// from being impersonated, and every role with elevated reach belongs in that
// answer even if it does not carry a blanket bypass.
var adminRoleSlugs = map[string]struct{}{
	"tenant_admin":  {},
	"admin":         {},
	"super_admin":   {},
	"org_admin":     {},
	"support_admin": {},
}

// ImpersonationResult is the response body of a successful impersonation.
type ImpersonationResult struct {
	// AccessToken is the impersonation JWT, marked impersonated.
	AccessToken string `json:"access_token"`
	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the token lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
	// ImpersonatedUser is the target's public profile.
	ImpersonatedUser UserInfo `json:"impersonated_user"`
	// ImpersonatorID identifies the admin who initiated the session.
	ImpersonatorID string `json:"impersonator_id"`
	// SessionID correlates the token, the webhook event and the audit trail.
	SessionID string `json:"session_id"`
}

// UserInfo is the target user's profile as returned to the impersonating admin.
type UserInfo struct {
	// ID is the target's user ID.
	ID string `json:"id"`
	// Email is the target's primary address.
	Email string `json:"email"`
	// Name is the target's display name, omitted when unset.
	Name *string `json:"name,omitempty"`
	// Status is the account status, always "active" for a successful call.
	Status string `json:"status"`
	// EmailVerified reports whether the primary address is verified.
	EmailVerified bool `json:"email_verified"`
}

// WebhookDispatcher delivers tenant webhook events.
type WebhookDispatcher interface {
	// Dispatch queues an event for delivery. It does not block the caller.
	Dispatch(tenantID, eventType string, data map[string]interface{})
}

// EmailProvider sends transactional mail.
type EmailProvider interface {
	// Send delivers one message with both HTML and plain-text bodies.
	Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error
}

// PermissionChecker answers whether a user holds a permission.
type PermissionChecker interface {
	// HasPermission reports whether userID holds requiredPerm.
	HasPermission(ctx context.Context, userID string, requiredPerm string) (bool, error)
}

// Service applies the impersonation rules and issues impersonation tokens.
type Service struct {
	// factory produces the tenant-scoped ORM client.
	factory *clientfactory.ClientFactory
	// cfg supplies the token signing secret.
	cfg *config.Config
	// dispatcher publishes the user.impersonated event; nil disables it.
	dispatcher WebhookDispatcher
	// emailProvider sends the transparency notice; nil disables it.
	emailProvider EmailProvider
	// permChecker enforces users:impersonate; nil disables the check.
	permChecker PermissionChecker
}

// appName returns the product name shown in the notification a user receives when support
// accesses their account. Falls back to a constant when Config supplies none, so the mail can
// never render a blank product name.
func (s *Service) appName() string {
	if s.cfg != nil && s.cfg.AppName != "" {
		return s.cfg.AppName
	}
	return "Authn Platform"
}

// NewService constructs an impersonation service. The variadic arguments are
// matched by interface, so a caller may supply any combination of a
// WebhookDispatcher, an EmailProvider and a PermissionChecker — or a single
// value implementing several — in any order. An omitted collaborator disables
// the behaviour it drives rather than failing.
func NewService(factory *clientfactory.ClientFactory, cfg *config.Config, dispatcher ...interface{}) *Service {
	svc := &Service{
		factory: factory,
		cfg:     cfg,
	}
	for _, arg := range dispatcher {
		if d, ok := arg.(WebhookDispatcher); ok {
			svc.dispatcher = d
		}
		if ep, ok := arg.(EmailProvider); ok {
			svc.emailProvider = ep
		}
		if pc, ok := arg.(PermissionChecker); ok {
			svc.permChecker = pc
		}
	}
	return svc
}

// IsUserAdmin reports whether the user holds any role in adminRoleSlugs. A
// failed role lookup reports false, so an unreadable role list never blocks a
// legitimate support session; RestrictAdminImpersonation is a policy guard, not
// the authorization boundary, which is the caller's own permission check.
func (s *Service) IsUserAdmin(ctx context.Context, userID string) bool {
	client := s.factory.GetClient(ctx, "", "")
	userRoles, err := client.UserRole.Query().
		Where(userrole.UserID(userID)).
		WithRole().
		All(ctx)
	if err == nil {
		for _, ur := range userRoles {
			if ur.Edges.Role != nil {
				if _, ok := adminRoleSlugs[ur.Edges.Role.Slug]; ok {
					return true
				}
			}
		}
	}
	return false
}

// ExecuteImpersonation applies every impersonation rule and, on success, returns
// a signed impersonation token for the target user.
//
// The checks run in order: the feature must be enabled, caller and target must
// differ, the caller must hold users:impersonate, the request must satisfy
// policy bounds, the target must exist and be active, must not be an
// administrator when policy restricts that, and must have opted in when policy
// requires it. Each failure returns its matching sentinel above; a request that
// violates the policy bounds returns the validator's error, and a token that
// cannot be signed returns a wrapped error.
//
// The permission check is skipped for a secret-key caller (an impersonatorID
// prefixed "key_") and when no PermissionChecker is configured, because neither
// resolves to a user whose roles can be read; those callers are already gated by
// admin authentication at the middleware.
//
// The session length is the smaller of the requested duration and the policy
// cap, defaulting to the cap when unspecified, so a caller can shorten its own
// session but never extend it.
func (s *Service) ExecuteImpersonation(ctx context.Context, tenantID string, env string, impersonatorID string, targetUserID string, req policy.ImpersonateRequest, pol policy.ImpersonationPolicy) (*ImpersonationResult, error) {
	if !pol.Enabled {
		return nil, ErrImpersonationDisabled
	}

	if impersonatorID == targetUserID {
		return nil, ErrCannotImpersonateSelf
	}

	if s.permChecker != nil && impersonatorID != "" && !strings.HasPrefix(impersonatorID, "key_") {
		allowed, err := s.permChecker.HasPermission(ctx, impersonatorID, "users:impersonate")
		if err != nil || !allowed {
			// A lookup failure denies: an unverifiable permission is not a held
			// permission.
			return nil, ErrInsufficientPermissions
		}
	}

	if err := policy.ValidateImpersonateRequest(req, pol); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, env)

	targetUser, err := client.User.Get(ctx, targetUserID)
	if err != nil || targetUser == nil {
		return nil, ErrUserNotFound
	}

	if targetUser.Status != "active" {
		return nil, ErrUserNotActive
	}

	if pol.RestrictAdminImpersonation && s.IsUserAdmin(ctx, targetUser.ID) {
		return nil, ErrCannotImpersonateAdmin
	}

	if pol.RequireUserOptIn {
		optIn, _ := targetUser.Metadata["support_access_enabled"].(bool)
		if !optIn {
			return nil, ErrUserOptInRequired
		}
	}

	durationMinutes := req.DurationMinutes
	if durationMinutes <= 0 {
		durationMinutes = pol.MaxDurationMinutes
	}
	if durationMinutes > pol.MaxDurationMinutes {
		durationMinutes = pol.MaxDurationMinutes
	}
	dur := time.Duration(durationMinutes) * time.Minute

	accessToken, err := jwt.IssueImpersonationToken(
		targetUser.ID,
		tenantID,
		env,
		targetUser.Email,
		targetUser.Name,
		"", // Role claim: an impersonated session carries no role of its own.
		impersonatorID,
		dur,
		s.cfg.EncryptionKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed issuing impersonation token: %w", err)
	}

	var namePtr *string
	if targetUser.Name != "" {
		namePtr = &targetUser.Name
	}

	sessionID := fmt.Sprintf("ses_imp_%d", time.Now().UnixNano())

	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "user.impersonated", map[string]interface{}{
			"target_user_id":    targetUser.ID,
			"target_user_email": targetUser.Email,
			"impersonator_id":   impersonatorID,
			"duration_minutes":  durationMinutes,
			"reason":            req.Reason,
			"ticket_id":         req.TicketID,
			"session_id":        sessionID,
		})
	}

	// Transparency notice to the user whose account is being accessed. It is sent
	// off the request path: a mail failure must not deny a support session that
	// has already passed every policy check.
	if pol.EmailNotificationPolicy == "IMMEDIATE" && s.emailProvider != nil {
		go func(toEmail, userName, reason, ticketID string, mins int) {
			htmlBody, textBody, err := email.RenderImpersonationEmail(email.ImpersonationEmailData{
				UserName:        userName,
				AdminName:       "",
				Reason:          reason,
				TicketID:        ticketID,
				DurationMinutes: mins,
				AppName:         s.appName(),
			})
			if err == nil {
				// A fresh context, because this goroutine outlives the request, but
				// a scoped one: the sandbox reads the environment off it to decide
				// whether a test-environment notice is captured or mailed to the
				// account holder for real.
				sendCtx := privacy.NewContext(context.Background(), tenantID, "", env)
				_ = s.emailProvider.Send(sendCtx, toEmail, email.SubjectImpersonation, htmlBody, textBody)
			}
		}(targetUser.Email, targetUser.Name, req.Reason, req.TicketID, durationMinutes)
	}

	return &ImpersonationResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(dur.Seconds()),
		ImpersonatedUser: UserInfo{
			ID:            targetUser.ID,
			Email:         targetUser.Email,
			Name:          namePtr,
			Status:        string(targetUser.Status),
			EmailVerified: targetUser.EmailVerified,
		},
		ImpersonatorID: impersonatorID,
		SessionID:      sessionID,
	}, nil
}
