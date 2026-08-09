/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/noop.go
 * Tier: Internal Service Package / No-op Email Driver
 *
 * An EmailProvider that logs instead of sending, selected when no delivery
 * backend is configured.
 *
 * This is what a fresh checkout runs on: a new clone has no SMTP server and no
 * provider account, and signup still has to complete. It is also what keeps the
 * test suite from sending real mail.
 *
 * The log line records recipient and subject but never the body, which carries
 * verification and magic links — credentials in their own right, and not
 * something to leave sitting in a log file.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"context"
	"log"
)

// NoopProvider discards messages after recording that they were requested.
type NoopProvider struct{}

// NewNoopProvider constructs a provider that sends nothing.
func NewNoopProvider() *NoopProvider {
	return &NoopProvider{}
}

// Send logs the recipient and subject, then reports success.
//
// It never fails. Callers treat a delivery error as a request failure, and a
// driver whose whole purpose is to not send has nothing to report.
func (p *NoopProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	log.Printf("[Email::Noop] Suppressed email to: %s | Subject: %s", to, subject)
	return nil
}
