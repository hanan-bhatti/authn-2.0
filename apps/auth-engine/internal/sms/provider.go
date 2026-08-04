/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/provider.go
 * Tier: Internal Service Package / SMS Provider Abstraction
 *
 * Description: Interface definition for pluggable SMS and WhatsApp drivers (Twilio, MessageBird, AWS SNS).
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import "context"

// SMSProvider defines the abstraction contract for sending SMS/WhatsApp messages.
type SMSProvider interface {
	SendSMS(ctx context.Context, toPhoneNumber string, message string) error
}
