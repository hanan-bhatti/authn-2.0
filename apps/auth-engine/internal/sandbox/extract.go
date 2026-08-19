/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sandbox/extract.go
 * Tier: Internal Service Package / Sandbox Capture Enrichment
 *
 * Lifts the parts of a message a test harness needs out of the rendered body at
 * capture time: the one-time code, the action link, and which template produced
 * it.
 *
 * These are stored as their own columns so completing a flow against the sandbox
 * does not mean parsing rendered HTML. The rendering is styling that changes
 * freely; the code and the link are the contract, and a harness that reads them
 * from structured fields keeps working across a redesign.
 *
 * Every extractor is deliberately strict. A loose match here is worse than no
 * match: a harness reading a wrong value from these fields fails in a way that
 * looks like the engine generated the wrong credential, which is a long way from
 * the actual cause.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sandbox

import (
	"regexp"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/email"
)

// otpPattern matches a standalone run of exactly six digits, which is the shape
// of every code this engine generates.
//
// The neighbouring characters are part of the match rather than a lookaround,
// which RE2 does not offer, so the digits are read from the second submatch. Both
// classes exclude '#' specifically: an inlined stylesheet is full of hex colours,
// and one of the palette's own values is six digits with no letters in it, so a
// pattern that ignored the leading '#' would report a border colour as the user's
// verification code.
var otpPattern = regexp.MustCompile(`(^|[^#0-9A-Za-z])([0-9]{6})([^0-9A-Za-z]|$)`)

// linkPattern matches an absolute URL carrying a token query parameter.
//
// A credential-bearing link is recognised by that parameter rather than by being
// a URL, because a rendered message contains the product's own links as well and
// the only one worth lifting out is the one that authenticates. The trailing
// class stops at the quote or angle bracket that closes an href, so the match is
// the URL and not the markup around it.
var linkPattern = regexp.MustCompile(`https?://[^\s"'<>]*[?&]token=[A-Za-z0-9._~%-]+`)

// templateBySubject maps a subject line to the identifier of the template that
// produced it.
//
// The keys are the sender's own constants rather than copies of their text, so a
// reworded subject changes one value and every entry here still resolves. An
// unrecognised subject yields an empty template rather than a guess: this field
// exists so a harness can assert on which message was triggered, and a wrong
// answer would defeat it more thoroughly than an absent one.
var templateBySubject = map[string]string{
	email.SubjectEmailVerification: "email_verification",
	email.SubjectMagicLink:         "magic_link",
	email.SubjectTwoFactorCode:     "two_factor_code",
	email.SubjectImpersonation:     "impersonation_notice",
	email.SubjectEmailChange:       "email_change",
	email.SubjectRecoveryEmail:     "recovery_email_verification",
}

// smsTemplate labels a captured text message.
//
// SMS carries a second-factor code and nothing else, so the channel identifies
// the template on its own and there is no subject line to classify.
const smsTemplate = "two_factor_code"

// extractOTP returns the six-digit code a body carries, or an empty string when
// it carries none.
//
// Only the first match is returned. A message carrying two codes would be a
// defect in the template rather than something to resolve here.
func extractOTP(body string) string {
	match := otpPattern.FindStringSubmatch(body)
	if match == nil {
		return ""
	}
	return match[2]
}

// extractLink returns the first credential-bearing URL a body carries, or an
// empty string when it carries none.
func extractLink(body string) string {
	return linkPattern.FindString(body)
}

// classifyEmail returns the template identifier for a subject line, or an empty
// string when the subject is not one the engine sends.
func classifyEmail(subject string) string {
	return templateBySubject[subject]
}
