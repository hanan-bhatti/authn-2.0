/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/factory.go
 * Tier: Internal Service Package / SMS Driver Factory
 *
 * Description: Factory constructor that instantiates the requested SMSProvider
 *              driver based on environment configuration (twilio, messagebird, aws_sns, noop).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"fmt"
	"strings"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
)

// NewSMSProvider instantiates the appropriate SMSProvider driver based on cfg.SMSDriver.
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

	case "aws_sns", "sns":
		return NewAWSSNSProvider(cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSRegion), nil

	case "noop", "none", "disabled", "":
		return NewNoopProvider(), nil

	default:
		return nil, fmt.Errorf("unsupported SMS_DRIVER '%s': expected 'twilio', 'messagebird', 'aws_sns', or 'noop'", cfg.SMSDriver)
	}
}
