/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sms/provider.go
 * Tier: Internal Service Package / SMS Driver Interface
 *
 * The contract every SMS backend implements, and the timeout they share.
 *
 * SMS carries second-factor codes and account alerts. It is the weakest of the
 * second factors offered — messages traverse carrier networks, are readable on
 * a locked screen, and are the target of SIM-swap attacks — so it is offered as
 * one option among several rather than as the default.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sms

import (
	"context"
	"time"
)

// providerHTTPTimeout caps a single send against a provider's REST API,
// covering connection, request and response together.
//
// A second-factor code is sent while the user waits on a login screen, so a
// stalled provider has to fail rather than hold the request open: Go's default
// HTTP client waits indefinitely, which turns a carrier outage into exhausted
// request handlers instead of failed sends.
const providerHTTPTimeout = 10 * time.Second

// SMSProvider sends text messages. Implementations must be safe for concurrent
// use, since one instance is shared across all request handlers.
type SMSProvider interface {
	// SendSMS delivers message to toPhoneNumber, which callers supply in E.164
	// form.
	//
	// Returns an error when the provider rejects the message or is unreachable.
	// A nil error means the provider accepted it for delivery, not that it
	// reached the handset — carrier delivery is asynchronous and not observable
	// here.
	SendSMS(ctx context.Context, toPhoneNumber string, message string) error
}
