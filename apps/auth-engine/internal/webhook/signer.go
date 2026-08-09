/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/signer.go
 * Tier: Cryptographic Security Layer
 *
 * Generates webhook signing secrets and produces the HMAC signatures that let a
 * receiver prove a payload came from this engine.
 *
 * A webhook arrives at a URL anyone on the internet can post to, so the
 * signature is the only thing separating a real event from a forged one. It
 * covers a timestamp as well as the body, and receivers reject stale
 * timestamps: signing the body alone would leave a captured delivery replayable
 * forever, since a replayed payload carries a signature that verifies
 * perfectly.
 *
 * VerifySignature is the receiver's half of the contract. The engine does not
 * call it in normal operation — it is here so that integrators have a reference
 * implementation, and so the signing format is exercised by the same code that
 * consumes it.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// SecretPrefix marks a value as a webhook signing secret, so a leaked
	// credential is identifiable on sight and by secret-scanning tools.
	SecretPrefix = "whsec_"

	// DefaultToleranceSec is the replay window, in seconds, applied when a
	// receiver specifies none.
	//
	// Five minutes trades replay exposure against clock skew: too tight and
	// legitimate deliveries fail on servers whose clocks drift, too loose and a
	// captured request stays replayable. The window applies in both directions,
	// so a receiver running ahead of the engine is tolerated as well.
	DefaultToleranceSec = 300

	// secretRandomBytes is the entropy behind a signing secret, in bytes,
	// rendered as 48 hex characters. At 192 bits it is far beyond guessing
	// while keeping the secret short enough to paste into a receiver's
	// configuration.
	secretRandomBytes = 24
)

var (
	// ErrInvalidSignatureHeader means the header is missing, malformed, or
	// lacks the timestamp or signature component.
	ErrInvalidSignatureHeader = errors.New("invalid X-Authn-Signature header format")
	// ErrSignatureMismatch means the signature does not match the body under
	// the shared secret: the payload was altered, or it was not signed by this
	// engine.
	ErrSignatureMismatch = errors.New("webhook signature mismatch")
	// ErrTimestampExpired means the timestamp falls outside the tolerance
	// window, which is what a replayed delivery looks like.
	ErrTimestampExpired = errors.New("webhook request timestamp is outside acceptable tolerance window (replay attack detected)")
)

// GenerateSecretKey creates a signing secret for a new endpoint.
//
// Returns an error only when the system random source fails. That is fatal
// rather than retryable: a predictable secret lets anyone forge deliveries to
// that endpoint, which is precisely what the signature exists to prevent.
func GenerateSecretKey() (string, error) {
	bytes := make([]byte, secretRandomBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for webhook secret: %w", err)
	}
	return SecretPrefix + hex.EncodeToString(bytes), nil
}

// HashSecret returns the SHA-256 digest of a secret, used as a uniqueness index
// so collisions can be detected without storing secrets in a searchable form.
//
// This is not the at-rest protection: secrets are stored encrypted, and this
// digest exists purely to make the collision check a single indexed lookup. No
// stretching is applied and none is needed, since the input is a 192-bit random
// value rather than a password.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// SignPayload computes the signature for a payload at a given timestamp.
//
// The timestamp is prefixed to the body before signing, so it is covered by the
// signature and cannot be edited to slip a captured delivery back inside the
// replay window.
func SignPayload(secret string, timestamp int64, body []byte) string {
	signedPayload := fmt.Sprintf("%d.%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	return hex.EncodeToString(mac.Sum(nil))
}

// FormatSignatureHeader renders the X-Authn-Signature header value, as in
// "t=1785877000,v1=9f8a2b3c...".
//
// The v1 label names the scheme, leaving room to publish a second algorithm
// later and let receivers accept both during a migration.
func FormatSignatureHeader(timestamp int64, signature string) string {
	return fmt.Sprintf("t=%d,v1=%s", timestamp, signature)
}

// VerifySignature checks a received delivery against the shared secret.
//
// body must be the exact bytes received. Re-encoding the parsed JSON changes
// key order and whitespace and produces a different signature, so a receiver
// has to capture the raw body before decoding it.
//
// A non-positive toleranceSec falls back to DefaultToleranceSec, so a caller
// that passes nothing still gets replay protection rather than none.
//
// Returns ErrInvalidSignatureHeader for a malformed header,
// ErrTimestampExpired when the delivery is outside the replay window, and
// ErrSignatureMismatch when the signature does not verify.
func VerifySignature(secret string, signatureHeader string, body []byte, toleranceSec int64) error {
	if toleranceSec <= 0 {
		toleranceSec = DefaultToleranceSec
	}

	parts := strings.Split(signatureHeader, ",")
	if len(parts) < 2 {
		return ErrInvalidSignatureHeader
	}

	// Unrecognised components are skipped rather than rejected, so a future
	// scheme adding a field does not break receivers written against this one.
	var timestampStr, receivedSig string
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestampStr = kv[1]
		case "v1":
			receivedSig = kv[1]
		}
	}

	if timestampStr == "" || receivedSig == "" {
		return ErrInvalidSignatureHeader
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return ErrInvalidSignatureHeader
	}

	// Freshness is checked before the signature so a replayed delivery is
	// rejected on the cheaper test. The window is applied symmetrically to
	// tolerate a receiver clock running ahead as well as behind.
	now := time.Now().Unix()
	if now-timestamp > toleranceSec || timestamp-now > toleranceSec {
		return ErrTimestampExpired
	}

	expectedSig := SignPayload(secret, timestamp, body)

	// Constant-time comparison. A byte-wise comparison that returns on the
	// first difference leaks how much of the signature was right, which is
	// enough to build a valid one byte at a time given repeated attempts.
	if subtle.ConstantTimeCompare([]byte(receivedSig), []byte(expectedSig)) != 1 {
		return ErrSignatureMismatch
	}

	return nil
}
