/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/aesgcm.go
 * Tier: Shared Package / Authenticated Encryption
 *
 * AES-256-GCM encryption of secrets held at rest: TOTP seeds, webhook signing
 * secrets, stored provider credentials.
 *
 * GCM is authenticated encryption, so decryption either returns the original
 * plaintext or fails. It never returns attacker-chosen plaintext. That property
 * is what makes it safe to store ciphertext in a database another component can
 * write to: a tampered row fails the tag check instead of silently decrypting
 * to something the attacker picked.
 *
 * Ciphertext is stored as base64 of nonce ‖ ciphertext ‖ tag — one opaque
 * string per secret, with no separate nonce column to keep in sync.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidCiphertext means the stored value is not decryptable input at
	// all: not valid base64, or too short to contain a nonce.
	ErrInvalidCiphertext = errors.New("invalid or corrupted ciphertext")
	// ErrDecryptionFailed means the GCM authentication tag did not verify. The
	// ciphertext was modified, or it was encrypted under a different key —
	// typically the encryption key was rotated without re-encrypting rows.
	ErrDecryptionFailed = errors.New("decryption failed or authentication tag mismatch")
)

// EncryptAES256GCM encrypts plaintext under keyString and returns base64 of
// nonce ‖ ciphertext ‖ tag.
//
// keyString is reduced to a 256-bit key with a single SHA-256 pass. That is a
// key derivation, not a password KDF: it stretches nothing. The configured
// encryption key must therefore be high-entropy random material, not a
// human-chosen passphrase, since a guessable passphrase is as cheap to brute
// force as its own entropy.
//
// Returns an error when the key is empty or the system random source fails.
func EncryptAES256GCM(plaintext string, keyString string) (string, error) {
	if keyString == "" {
		return "", errors.New("encryption key cannot be empty")
	}

	key := sha256.Sum256([]byte(keyString))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM block: %w", err)
	}

	// A fresh random nonce per encryption is the one non-negotiable GCM rule.
	// Encrypting two messages under the same key and nonce reveals the XOR of
	// their plaintexts and leaks the authentication subkey, which lets an
	// attacker forge tags for arbitrary ciphertext under that key. At 96 bits
	// from a CSPRNG, collisions stay negligible well past this system's volume.
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// Seal appends to its first argument, so passing nonce prefixes the output
	// with it — Decrypt reads it back off the front.
	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES256GCM reverses EncryptAES256GCM.
//
// Returns ErrInvalidCiphertext when the input is not well-formed, and
// ErrDecryptionFailed when the authentication tag does not verify. Both are
// returned bare, without the underlying cipher error: the distinction between
// "wrong key" and "modified ciphertext" is useful to an attacker probing which
// stored rows they can influence, and useless to the caller, which cannot
// recover from either.
func DecryptAES256GCM(ciphertextBase64 string, keyString string) (string, error) {
	if keyString == "" {
		return "", errors.New("encryption key cannot be empty")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidCiphertext, err)
	}

	key := sha256.Sum256([]byte(keyString))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM block: %w", err)
	}

	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}
