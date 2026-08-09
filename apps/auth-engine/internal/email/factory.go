/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/factory.go
 * Tier: Internal Service Package / Email Driver Selection
 *
 * Turns the configured driver name into a live EmailProvider.
 *
 * Selection happens once at startup and fails loudly. A driver named with its
 * credential missing is a configuration mistake, and the useful moment to say
 * so is before the server accepts traffic — not on the first password reset,
 * where the user sees a generic failure and nobody sees the cause.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"fmt"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

// fallbackFromAddress is the sender used when configuration names none.
//
// The .local suffix is reserved and undeliverable, which is deliberate: mail
// sent from an unconfigured deployment bounces visibly instead of appearing to
// originate from a real domain the operator does not own.
const fallbackFromAddress = "noreply@authn.local"

// NewEmailProvider builds the provider named by cfg.EmailDriver.
//
// A nil config yields the no-op driver, so tooling that runs without the
// configuration layer loaded still constructs successfully.
//
// Recognised drivers are smtp, resend, sendgrid, postmark, aws_ses (or ses) and
// noop (or none, or disabled). An empty driver means smtp, matching the config
// layer's default. Returns an error when the driver name is unknown, or when a
// named provider's credential is absent — the two failures an operator can fix
// by editing configuration.
func NewEmailProvider(cfg *config.Config) (EmailProvider, error) {
	if cfg == nil {
		return NewNoopProvider(), nil
	}

	driver := strings.ToLower(strings.TrimSpace(cfg.EmailDriver))
	from := cfg.EmailFromAddress
	if from == "" {
		from = fallbackFromAddress
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

	// SES credentials are not required here: AWS resolves them from the
	// instance role or ambient environment when none are configured, so absence
	// is a valid deployment rather than a misconfiguration.
	case "aws_ses", "ses":
		return NewAWSSESProvider(cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSRegion, from), nil

	case "noop", "none", "disabled":
		return NewNoopProvider(), nil

	default:
		return nil, fmt.Errorf("unsupported EMAIL_DRIVER '%s': expected 'smtp', 'resend', 'sendgrid', 'postmark', 'aws_ses', or 'noop'", cfg.EmailDriver)
	}
}
