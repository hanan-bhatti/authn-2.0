/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/factory.go
 * Tier: Internal Service Package / SMS Driver Selection
 *
 * Turns the configured driver name into a live SMSProvider.
 *
 * Selection happens once at startup and fails loudly. A driver named with its
 * credentials missing is a configuration mistake, and the useful moment to say
 * so is before the server accepts traffic — not when a user is waiting on a
 * second-factor code that will never arrive.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"fmt"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

// NewSMSProvider builds the provider named by cfg.SMSDriver.
//
// A nil config yields the no-op driver, so tooling that runs without the
// configuration layer loaded still constructs successfully.
//
// Recognised drivers are twilio, messagebird, aws_sns (or sns) and noop (or
// none, or disabled). An empty driver means noop, so SMS stays off until a
// deployment turns it on. Returns an error when the driver name is unknown, or
// when a named provider's credentials are absent.
func NewSMSProvider(cfg *config.Config) (SMSProvider, error) {
	if cfg == nil {
		return NewNoopProvider(), nil
	}

	driver := strings.ToLower(strings.TrimSpace(cfg.SMSDriver))

	switch driver {
	case "twilio":
		if cfg.TwilioAccountSID == "" || cfg.TwilioAuthToken == "" {
			return nil, fmt.Errorf("SMS_DRIVER is 'twilio' but TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN is not set")
		}
		return NewTwilioProvider(cfg.TwilioAccountSID, cfg.TwilioAuthToken, cfg.TwilioFromNumber), nil

	case "messagebird":
		if cfg.MessageBirdAccessKey == "" {
			return nil, fmt.Errorf("SMS_DRIVER is 'messagebird' but MESSAGEBIRD_ACCESS_KEY is not set")
		}
		return NewMessageBirdProvider(cfg.MessageBirdAccessKey, cfg.MessageBirdOriginator), nil

	// SNS credentials are not required here: AWS resolves them from the
	// instance role or ambient environment when none are configured, so absence
	// is a valid deployment rather than a misconfiguration.
	case "aws_sns", "sns":
		return NewAWSSNSProvider(cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSRegion), nil

	case "noop", "none", "disabled", "":
		return NewNoopProvider(), nil

	default:
		return nil, fmt.Errorf("unsupported SMS_DRIVER '%s': expected 'twilio', 'messagebird', 'aws_sns', or 'noop'", cfg.SMSDriver)
	}
}
