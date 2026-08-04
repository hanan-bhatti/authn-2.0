/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/noop.go
 * Tier: Internal Service Package / SMS Drivers
 *
 * Description: No-op / Console logger implementation of SMSProvider interface.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"context"
	"log"
)

// NoopProvider logs SMS messages to stdout without transmitting over external networks.
type NoopProvider struct{}

// NewNoopProvider constructs a new NoopProvider instance.
func NewNoopProvider() *NoopProvider {
	return &NoopProvider{}
}

// SendSMS logs the target phone number and message contents.
func (p *NoopProvider) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	log.Printf("[SMS NO-OP DRIVER] To: %s | Message: %s", toPhoneNumber, message)
	return nil
}
