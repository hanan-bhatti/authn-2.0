/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/email/subjects.go
 * Tier: Internal Service Package / Email Subject Lines
 *
 * The subject line of every transactional message the engine sends.
 *
 * These sit here rather than inline at each call site so that a consumer which
 * has to recognise a message by its subject keys off the same constant the
 * sender uses. The sandbox inbox does exactly that when it labels a captured
 * message with the template that produced it: with a shared constant a reworded
 * subject changes one value and the label still resolves, where two independent
 * string literals would drift apart silently and leave captured messages
 * unlabelled.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package email

const (
	// SubjectEmailVerification confirms ownership of a new account's address.
	SubjectEmailVerification = "Verify your email address"
	// SubjectMagicLink carries a passwordless sign-in link.
	SubjectMagicLink = "Log in to Authn Platform"
	// SubjectTwoFactorCode carries a second-factor code, sent when SMS delivery
	// is unavailable.
	SubjectTwoFactorCode = "Your Authn 2FA Verification Code"
	// SubjectImpersonation notifies an account holder that support accessed
	// their account.
	SubjectImpersonation = "🛡️ Security Notice: Support Access to Your Account"
	// SubjectEmailChange confirms ownership of an address an account is moving
	// to.
	SubjectEmailChange = "Verify your new email address"
	// SubjectRecoveryEmail confirms ownership of a secondary address used for
	// account recovery.
	SubjectRecoveryEmail = "Verify your secondary recovery email"
)
