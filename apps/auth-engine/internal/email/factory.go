/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/factory.go
 * Tier: Internal Service Package / Email Driver Factory
 *
 * Description: Factory constructor that instantiates the requested EmailProvider
 *              driver based on environment configuration (smtp, resend, sendgrid, postmark, aws_ses, noop).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"fmt"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

// NewEmailProvider instantiates the appropriate EmailProvider driver based on cfg.EmailDriver.
func NewEmailProvider(cfg *config.EnvConfig) (EmailProvider, error) {
	if cfg == nil {
		return NewNoopProvider(), nil
	}

	driver := strings.ToLower(strings.TrimSpace(cfg.EmailDriver))
	from := cfg.EmailFromAddress
	if from == "" {
		from = "noreply@authn.local"
	}

	switch driver {
	case "smtp", "":
		return NewSMTPProvider(SMTPConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			Username: cfg.SMTPUser,
			Password: cfg.SMTPPassword,
			From:     from,
		}), nil

	case "resend":
		if cfg.ResendAPIKey == "" {
			return nil, fmt.Errorf("EMAIL_DRIVER is 'resend' but RESEND_API_KEY is not set")
		}
		return NewResendProvider(cfg.ResendAPIKey, from), nil

	case "sendgrid":
		if cfg.SendGridAPIKey == "" {
			return nil, fmt.Errorf("EMAIL_DRIVER is 'sendgrid' but SENDGRID_API_KEY is not set")
		}
		return NewSendGridProvider(cfg.SendGridAPIKey, from), nil

	case "postmark":
		if cfg.PostmarkServerToken == "" {
			return nil, fmt.Errorf("EMAIL_DRIVER is 'postmark' but POSTMARK_SERVER_TOKEN is not set")
		}
		return NewPostmarkProvider(cfg.PostmarkServerToken, from), nil

	case "aws_ses", "ses":
		return NewAWSSESProvider(cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSRegion, from), nil

	case "noop", "none", "disabled":
		return NewNoopProvider(), nil

	default:
		return nil, fmt.Errorf("unsupported EMAIL_DRIVER '%s': expected 'smtp', 'resend', 'sendgrid', 'postmark', 'aws_ses', or 'noop'", cfg.EmailDriver)
	}
}
