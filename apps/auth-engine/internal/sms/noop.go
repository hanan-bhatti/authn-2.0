/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/noop.go
 * Tier: Internal Service Package / No-op SMS Driver
 *
 * An SMSProvider that logs instead of sending, selected when no SMS backend is
 * configured.
 *
 * This is what a fresh checkout and the test suite run on: neither has carrier
 * credentials, and both need second-factor flows to complete.
 *
 * The log line includes the message body, which during development is the point
 * — it is how a developer reads the code they were sent. That also makes this
 * driver unsuitable for any deployment serving real users, since it writes
 * one-time codes to the log in clear text.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"context"
	"log"
)

// NoopProvider discards messages after logging them.
type NoopProvider struct{}

// NewNoopProvider constructs a provider that sends nothing.
func NewNoopProvider() *NoopProvider {
	return &NoopProvider{}
}

// SendSMS logs the recipient and message, then reports success.
//
// It never fails: callers treat a send error as a request failure, and a driver
// whose whole purpose is to not send has nothing to report.
func (p *NoopProvider) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	log.Printf("[SMS NO-OP DRIVER] To: %s | Message: %s", toPhoneNumber, message)
	return nil
}
