/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/provider.go
 * Tier: Internal Service Package / Email Driver Interface
 *
 * Description: Defines the core EmailProvider interface contract for pluggable
 *              email drivers (SMTP, Resend, SendGrid, Postmark, AWS SES).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import "context"

// EmailProvider defines the contract for sending emails across all drivers.
type EmailProvider interface {
	// Send delivers an email with both HTML and plain-text alternatives.
	Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error
}
