/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/signer.go
 * Tier: Cryptographic Security Layer
 *
 * Description: Secret key generator with 'whsec_' prefix, SHA-256 secret hashing
 *              for collision checks, HMAC-SHA256 payload signing, and constant-time verification.
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
	SecretPrefix       = "whsec_"
	DefaultToleranceSec = 300 // 5-minute replay attack tolerance window
)

var (
	ErrInvalidSignatureHeader = errors.New("invalid X-Authn-Signature header format")
	ErrSignatureMismatch      = errors.New("webhook signature mismatch")
	ErrTimestampExpired       = errors.New("webhook request timestamp is outside acceptable tolerance window (replay attack detected)")
)

// GenerateSecretKey creates a cryptographically secure 256-bit secret key starting with 'whsec_'.
func GenerateSecretKey() (string, error) {
	bytes := make([]byte, 24) // 192 bits of entropy -> 48 hex chars
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for webhook secret: %w", err)
	}
	return SecretPrefix + hex.EncodeToString(bytes), nil
}

// HashSecret computes the SHA-256 hex digest of a raw secret key.
// Used for uniqueness indexing and collision checking without storing unencrypted secrets.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// SignPayload computes the HMAC-SHA256 signature for a raw payload bytes slice at a given timestamp.
// Signature format: hex(HMAC-SHA256(secret, "timestamp.rawBody"))
func SignPayload(secret string, timestamp int64, body []byte) string {
	signedPayload := fmt.Sprintf("%d.%s", timestamp, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	return hex.EncodeToString(mac.Sum(nil))
}

// FormatSignatureHeader constructs the standard X-Authn-Signature header value (e.g. "t=1785877000,v1=9f8a2b3c...").
func FormatSignatureHeader(timestamp int64, signature string) string {
	return fmt.Sprintf("t=%d,v1=%s", timestamp, signature)
}

// VerifySignature parses the X-Authn-Signature header, checks timestamp freshness against tolerance,
// and performs constant-time HMAC-SHA256 verification.
func VerifySignature(secret string, signatureHeader string, body []byte, toleranceSec int64) error {
	if toleranceSec <= 0 {
		toleranceSec = DefaultToleranceSec
	}

	parts := strings.Split(signatureHeader, ",")
	if len(parts) < 2 {
		return ErrInvalidSignatureHeader
	}

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

	// Replay attack check
	now := time.Now().Unix()
	if now-timestamp > toleranceSec || timestamp-now > toleranceSec {
		return ErrTimestampExpired
	}

	expectedSig := SignPayload(secret, timestamp, body)

	// Constant-time signature comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(receivedSig), []byte(expectedSig)) != 1 {
		return ErrSignatureMismatch
	}

	return nil
}
