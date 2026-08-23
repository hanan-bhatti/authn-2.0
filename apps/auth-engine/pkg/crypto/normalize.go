/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/normalize.go
 * Tier: Shared Package / Password Hashing
 *
 * Unicode normalization of password input, applied before hashing and before
 * measurement.
 *
 * The same password can be typed as more than one byte sequence. "é" is either
 * U+00E9 or U+0065 U+0301 depending on keyboard, input method and platform, and
 * the two are indistinguishable on screen. Hashing the raw bytes makes those
 * two spellings different passwords, so an account created on macOS can be
 * impossible to sign into from Linux — with no error a user could act on,
 * because the password they typed is visibly correct.
 *
 * NFKC is the compatibility-composing form: it composes marks onto their base
 * characters and folds compatibility variants onto their canonical
 * equivalents, so fullwidth "ａ" and ASCII "a" agree. RFC 8265 specifies this
 * for passwords for exactly this reason.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package crypto

import "golang.org/x/text/unicode/norm"

// MaxPasswordInputBytes is the largest raw password the engine will normalize.
//
// It is a work bound rather than a policy rule. NFKC can expand its input
// several times over — U+FDFA alone becomes eighteen characters — so
// normalizing an unbounded field would let a small request allocate a large
// string, on a path that today rejects an over-long password without spending
// anything. Refusing above this ceiling keeps that path cheap.
//
// The value is four bytes per character at the engine's own character ceiling,
// which is the most a password of the maximum length can occupy. Normalization
// can shorten a string as well as lengthen it, so a raw input above this ceiling
// is not strictly guaranteed to be over-long once composed; a password of more
// than sixteen kilobytes of decomposed input is a stated engine limit rather
// than a policy the tenant chose.
const MaxPasswordInputBytes = 4096 * 4

// NormalizePassword returns password in Unicode NFKC form.
//
// Every hash and every verification runs through this, so the stored digest is
// always of the normalized form and the two cannot disagree. Input longer than
// MaxPasswordInputBytes is returned unchanged: it is over the engine's ceiling
// and will be refused by the length check, and normalizing it first would do
// the work this bound exists to avoid.
//
// Already-normal input — every ASCII password — costs a scan and no allocation.
func NormalizePassword(password string) string {
	if len(password) > MaxPasswordInputBytes {
		return password
	}
	return norm.NFKC.String(password)
}
