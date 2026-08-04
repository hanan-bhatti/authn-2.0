/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/crypto/aesgcm.go
 * Tier: Shared Package / Cryptography Utilities
 *
 * Description: AES-256-GCM authenticated encryption & decryption helper.
 *
 * Security Notice:
 *   - Derives a 256-bit key via SHA-256 from the secret key string.
 *   - Uses crypto/rand to generate a cryptographically safe unique 12-byte nonce per encryption.
 *   - Formats output as base64 encoded string: nonce + ciphertext.
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
	ErrInvalidCiphertext = errors.New("invalid or corrupted ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed or authentication tag mismatch")
)

// EncryptAES256GCM encrypts plaintext using AES-256-GCM with a derived 32-byte key.
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

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES256GCM decrypts a base64 encoded ciphertext using AES-256-GCM.
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
