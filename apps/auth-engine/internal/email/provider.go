/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/provider.go
 * Tier: Internal Service Package / Email Driver Interface
 *
 * The contract every email backend implements, and the timeout shared by the
 * HTTP-based ones.
 *
 * Delivery is pluggable because the choice is a deployment decision, not a
 * product one: a local checkout logs to the console, a self-hoster points at
 * their own SMTP relay, and a hosted deployment uses whichever API provider it
 * holds an account with. Nothing above this interface knows which is in use.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

import (
	"context"
	"time"
)

// providerHTTPTimeout caps a single delivery attempt against a provider's REST
// API, covering connection, request and response together.
//
// Sending happens on the request path for signup and password reset, so an
// unresponsive provider has to fail rather than hold the caller open: Go's
// default HTTP client waits indefinitely, which would turn a provider outage
// into exhausted request handlers instead of failed emails. Ten seconds sits
// well beyond these APIs' normal response time, so it trips on an outage rather
// than on a slow day.
const providerHTTPTimeout = 10 * time.Second

// EmailProvider sends transactional mail. Implementations must be safe for
// concurrent use, since one instance is shared across all request handlers.
type EmailProvider interface {
	// Send delivers one message carrying both HTML and plain-text alternatives.
	//
	// Both bodies are supplied so the recipient's client can choose; a provider
	// omits whichever is empty. It returns an error when the message is
	// rejected or the provider is unreachable. A nil error means the provider
	// accepted the message for delivery — not that it reached the recipient,
	// which happens asynchronously and is not observable here.
	Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error
}
