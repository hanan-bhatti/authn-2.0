/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/impersonation/service.go
 * Tier: Internal Feature Package / Impersonation Service
 *
 * Description: Core business logic for Admin User Impersonation (FR-14).
 *              Handles hierarchy checks, tenant bounds, step-up verification,
 *              and short-lived impersonation token issuance.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package impersonation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/jwt"
)

var (
	ErrImpersonationDisabled = errors.New("impersonation feature is disabled for this tenant")
	ErrUserNotFound          = errors.New("target user not found")
	ErrUserNotActive         = errors.New("cannot impersonate suspended or unverified user")
	ErrCannotImpersonateSelf = errors.New("cannot impersonate self")
	ErrCannotImpersonateAdmin = errors.New("cannot impersonate admin users")
	ErrUserOptInRequired     = errors.New("target user has not granted support access permission")
)

type ImpersonationResult struct {
	AccessToken     string   `json:"access_token"`
	TokenType       string   `json:"token_type"`
	ExpiresIn       int      `json:"expires_in"`
	ImpersonatedUser UserInfo `json:"impersonated_user"`
	ImpersonatorID  string   `json:"impersonator_id"`
	SessionID       string   `json:"session_id"`
}

type UserInfo struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	Name          *string `json:"name,omitempty"`
	Status        string  `json:"status"`
	EmailVerified bool    `json:"email_verified"`
}

type WebhookDispatcher interface {
	Dispatch(tenantID, eventType string, data map[string]interface{})
}

type EmailProvider interface {
	Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error
}

type Service struct {
	factory       *clientfactory.ClientFactory
	cfg           *config.EnvConfig
	dispatcher    WebhookDispatcher
	emailProvider EmailProvider
}

func NewService(factory *clientfactory.ClientFactory, cfg *config.EnvConfig, dispatcher ...interface{}) *Service {
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
	}
	return svc
}

// IsUserAdmin checks if a user holds an administrative role.
func (s *Service) IsUserAdmin(ctx context.Context, userID string) bool {
	client := s.factory.GetClient(ctx, "", "")
	userRoles, err := client.UserRole.Query().
		Where(userrole.UserID(userID)).
		WithRole().
		All(ctx)
	if err == nil {
		for _, ur := range userRoles {
			if ur.Edges.Role != nil {
				slug := ur.Edges.Role.Slug
				if slug == "tenant_admin" || slug == "admin" || slug == "super_admin" || slug == "org_admin" || slug == "support_admin" {
					return true
				}
			}
		}
	}
	return false
}

// ExecuteImpersonation validates rules and generates an impersonation token for the target user.
func (s *Service) ExecuteImpersonation(ctx context.Context, tenantID string, env string, impersonatorID string, targetUserID string, req policy.ImpersonateRequest, pol policy.ImpersonationPolicy) (*ImpersonationResult, error) {
	if !pol.Enabled {
		return nil, ErrImpersonationDisabled
	}

	if impersonatorID == targetUserID {
		return nil, ErrCannotImpersonateSelf
	}

	if err := policy.ValidateImpersonateRequest(req, pol); err != nil {
		return nil, err
	}

	client := s.factory.GetClient(ctx, tenantID, env)

	// Fetch Target User
	targetUser, err := client.User.Get(ctx, targetUserID)
	if err != nil || targetUser == nil {
		return nil, ErrUserNotFound
	}

	if targetUser.Status != "active" {
		return nil, ErrUserNotActive
	}

	// Hierarchy Check: Cannot impersonate another admin user if policy restricts it
	if pol.RestrictAdminImpersonation && s.IsUserAdmin(ctx, targetUser.ID) {
		return nil, ErrCannotImpersonateAdmin
	}

	// User Opt-In Check
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

	// Issue Impersonation Access Token JWT
	accessToken, err := jwt.IssueImpersonationToken(
		targetUser.ID,
		tenantID,
		env,
		targetUser.Email,
		targetUser.Name,
		"", // Target user role
		impersonatorID,
		dur,
		s.cfg.AuthnEncryptionKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed issuing impersonation token: %w", err)
	}

	var namePtr *string
	if targetUser.Name != "" {
		namePtr = &targetUser.Name
	}

	sessionID := fmt.Sprintf("ses_imp_%d", time.Now().UnixNano())

	// Dispatch user.impersonated Webhook Event asynchronously
	if s.dispatcher != nil {
		s.dispatcher.Dispatch(tenantID, "user.impersonated", map[string]interface{}{
			"target_user_id":   targetUser.ID,
			"target_user_email": targetUser.Email,
			"impersonator_id":  impersonatorID,
			"duration_minutes": durationMinutes,
			"reason":           req.Reason,
			"ticket_id":        req.TicketID,
			"session_id":       sessionID,
		})
	}

	// Dispatch User Transparency Notification Email
	if pol.EmailNotificationPolicy == "IMMEDIATE" && s.emailProvider != nil {
		go func(toEmail, userName, reason, ticketID string, mins int) {
			htmlBody, textBody, err := email.RenderImpersonationEmail(email.ImpersonationEmailData{
				UserName:        userName,
				AdminName:       "",
				Reason:          reason,
				TicketID:        ticketID,
				DurationMinutes: mins,
				AppName:         "Authn Platform",
			})
			if err == nil {
				_ = s.emailProvider.Send(context.Background(), toEmail, "🛡️ Security Notice: Support Access to Your Account", htmlBody, textBody)
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
