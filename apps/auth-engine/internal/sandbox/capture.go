/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sandbox/capture.go
 * Tier: Internal Service Package / Sandbox Delivery Interception
 *
 * Wraps the configured email and SMS providers so that a message sent while
 * acting in the test environment is stored instead of delivered.
 *
 * Interception happens at the provider interface rather than at each place the
 * engine decides to send. One wrap at startup therefore covers every sender the
 * engine has and every one it grows, which for a sandbox is a security property
 * and not a convenience: a send site somebody forgets to route through the
 * sandbox is a real message leaving a test environment, addressed to whoever the
 * fixture named.
 *
 * The tenant and environment are read from the context, which every
 * authenticating middleware has already populated for the privacy interceptors.
 * Nothing needs to be threaded through the provider signature for this to work.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sandbox

import (
	"context"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sandboxmessage"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/sms"
)

// capturing reports whether the caller's scope is one whose messages are held
// rather than delivered.
//
// Only an explicit test scope captures. An absent or bypassing scope delivers,
// which is the opposite of the default the settings split takes, and deliberately
// so: there an unknown environment reads as test because the narrow answer is the
// harmless one, whereas here the narrow answer would swallow a live password
// reset and lock a customer out of their own account. Sends made off the request
// path carry their scope explicitly so that they land on the right side of this.
func capturing(ctx context.Context) bool {
	p, ok := privacy.FromContext(ctx)
	if !ok || p.Bypass {
		return false
	}
	return p.TenantID != "" && p.Environment == string(sandboxmessage.EnvironmentTest)
}

// EmailCapturer is an email.EmailProvider that stores test-environment messages
// in the sandbox and delegates the rest.
type EmailCapturer struct {
	delegate email.EmailProvider
	store    *Store
}

// WrapEmail returns a provider that captures test-environment mail.
//
// A nil delegate or store returns the delegate untouched, so a deployment that
// fails to build the sandbox keeps its ordinary provider rather than ending up
// with one that silently discards mail.
func WrapEmail(delegate email.EmailProvider, store *Store) email.EmailProvider {
	if delegate == nil || store == nil {
		return delegate
	}
	return &EmailCapturer{delegate: delegate, store: store}
}

// Send stores the message when the caller is acting in the test environment, and
// hands it to the real provider otherwise.
//
// The HTML alternative is stored as the body because it is the richer of the two
// and what a console renders when an operator opens the message. The plain-text
// alternative goes to metadata, where it stays useful to anything reading the
// inbox as text without having to strip markup.
//
// A failed capture is returned as an error, matching what a provider does when it
// cannot accept a message: the callers that log and continue keep doing so, and
// the reason a message never arrived stays visible instead of being swallowed by
// the layer that was supposed to store it.
func (p *EmailCapturer) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	if !capturing(ctx) {
		return p.delegate.Send(ctx, to, subject, htmlBody, textBody)
	}

	body := htmlBody
	if body == "" {
		body = textBody
	}

	// The code is read from the plain-text alternative in preference to the HTML
	// one. Both carry the same code, and only one of them is wrapped in an
	// inlined stylesheet whose colour values a digit pattern has to be careful
	// around.
	codeSource := textBody
	if codeSource == "" {
		codeSource = htmlBody
	}

	metadata := map[string]interface{}{}
	if link := extractLink(codeSource); link != "" {
		metadata["link"] = link
	}
	if textBody != "" && textBody != body {
		metadata["text_body"] = textBody
	}

	_, err := p.store.Capture(ctx, Message{
		Channel:   sandboxmessage.ChannelEmail,
		Recipient: to,
		Subject:   subject,
		Body:      body,
		Template:  classifyEmail(subject),
		Code:      extractOTP(codeSource),
		Metadata:  metadata,
	})
	return err
}

// SMSCapturer is an sms.SMSProvider that stores test-environment messages in the
// sandbox and delegates the rest.
type SMSCapturer struct {
	delegate sms.SMSProvider
	store    *Store
}

// WrapSMS returns a provider that captures test-environment text messages.
//
// A nil delegate or store returns the delegate untouched, for the same reason
// WrapEmail does.
func WrapSMS(delegate sms.SMSProvider, store *Store) sms.SMSProvider {
	if delegate == nil || store == nil {
		return delegate
	}
	return &SMSCapturer{delegate: delegate, store: store}
}

// SendSMS stores the message when the caller is acting in the test environment,
// and hands it to the real provider otherwise.
//
// Capturing rather than sending is what makes SMS enrolment testable at all: the
// alternative is paying a carrier for every run of the second-factor test, to a
// handset that has to be in somebody's hand to read the code off.
func (p *SMSCapturer) SendSMS(ctx context.Context, toPhoneNumber string, message string) error {
	if !capturing(ctx) {
		return p.delegate.SendSMS(ctx, toPhoneNumber, message)
	}

	_, err := p.store.Capture(ctx, Message{
		Channel:   sandboxmessage.ChannelSms,
		Recipient: toPhoneNumber,
		Body:      message,
		Template:  smsTemplate,
		Code:      extractOTP(message),
	})
	return err
}
