/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/noop.go
 * Tier: Internal Service Package / No-op Email Driver Fallback
 *
 * Description: No-op email provider that logs outgoing email metadata to stdout
 *              when email delivery is disabled or set to "noop" driver.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"context"
	"log"
)

// NoopProvider logs email operations without delivering them.
type NoopProvider struct{}

// NewNoopProvider constructs a new NoopProvider.
func NewNoopProvider() *NoopProvider {
	return &NoopProvider{}
}

// Send logs email delivery parameters to standard output.
func (p *NoopProvider) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	log.Printf("[Email::Noop] Suppressed email to: %s | Subject: %s", to, subject)
	return nil
}
