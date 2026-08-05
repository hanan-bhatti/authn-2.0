/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/validator/validator.go
 * Tier: Security & Input Validation Layer
 *
 * Description: Universal input validation, string sanitization, numeric range guards,
 *              XSS script injection defenses, and image URL verifiers across all request DTOs.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package validator

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var (
	ErrInvalidEmail      = errors.New("invalid email address format")
	ErrEmailTooLong      = errors.New("email address exceeds maximum length of 254 characters")
	ErrStringTooShort    = errors.New("input string is shorter than required minimum length")
	ErrStringTooLong     = errors.New("input string exceeds maximum permitted length")
	ErrContainsControlCh = errors.New("input contains prohibited control characters or null bytes")
	ErrXSSDetected       = errors.New("input contains prohibited script or HTML injection payload")
	ErrInvalidImageURL   = errors.New("invalid image URL: must be a valid HTTP/HTTPS image URL or domain reference")
	ErrDisallowedScheme  = errors.New("prohibited URI scheme detected (only http:// and https:// are permitted)")
	ErrNumberOutOfRange  = errors.New("numeric value is outside permitted min/max range")
)

// Regex patterns for security checks
var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
	xssRegex      = regexp.MustCompile(`(?i)(<script|javascript:|data:text/html|vbscript:|onload=|onerror=|onclick=|<iframe|<object|<embed)`)
	imageExtRegex = regexp.MustCompile(`(?i)\.(png|jpg|jpeg|gif|webp|svg|ico|avif)(\?.*)?$`)
	domainRegex   = regexp.MustCompile(`^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(/.*)?$`)
)

// ValidateEmail checks RFC 5322 syntax, length, and control character absence.
func ValidateEmail(emailStr string) error {
	emailStr = strings.TrimSpace(emailStr)
	if emailStr == "" {
		return ErrInvalidEmail
	}
	if len(emailStr) > 254 {
		return ErrEmailTooLong
	}
	if ContainsControlChars(emailStr) {
		return ErrContainsControlCh
	}
	if !emailRegex.MatchString(emailStr) {
		return ErrInvalidEmail
	}
	return nil
}

// ContainsControlChars checks for null bytes or unprintable control characters (\x00 - \x1F, \x7F).
func ContainsControlChars(s string) bool {
	for _, r := range s {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') || r == 127 {
			return true
		}
	}
	return false
}

// ContainsXSS checks for potential XSS or script injection payloads.
func ContainsXSS(s string) bool {
	return xssRegex.MatchString(s)
}

// SanitizeString validates string length, checks control characters, and blocks XSS.
func SanitizeString(s string, minLen, maxLen int) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) < minLen {
		return "", fmt.Errorf("%w: minimum length is %d characters", ErrStringTooShort, minLen)
	}
	if maxLen > 0 && len(s) > maxLen {
		return "", fmt.Errorf("%w: maximum length is %d characters", ErrStringTooLong, maxLen)
	}
	if ContainsControlChars(s) {
		return "", ErrContainsControlCh
	}
	if ContainsXSS(s) {
		return "", ErrXSSDetected
	}
	return s, nil
}

// ValidateImageURL thoroughly verifies that an avatar/picture URL is safe and valid.
// Supports https://, http://, or domain paths like img.com/avatar.jpg.
// Rejects javascript:, file://, data:, and script code.
func ValidateImageURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", nil
	}

	if ContainsControlChars(rawURL) || ContainsXSS(rawURL) {
		return "", ErrXSSDetected
	}

	// Lowercase scheme check
	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "ftp:") || strings.HasPrefix(lower, "vbscript:") {
		return "", ErrDisallowedScheme
	}

	// Auto-prefix scheme if user provided domain format like "img.com/photo.png" or "cdn.acme.local/user.jpg"
	targetURL := rawURL
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		if domainRegex.MatchString(rawURL) {
			targetURL = "https://" + rawURL
		} else {
			return "", ErrInvalidImageURL
		}
	}

	u, err := url.ParseRequestURI(targetURL)
	if err != nil || u.Host == "" {
		return "", ErrInvalidImageURL
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", ErrDisallowedScheme
	}

	// Verify host is valid (no control chars or invalid symbols)
	for _, r := range u.Host {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != ':' {
			return "", ErrInvalidImageURL
		}
	}

	return targetURL, nil
}

// ValidateIntRange enforces inclusive minimum and maximum limits for integer parameters.
func ValidateIntRange(val int, minVal, maxVal int, fieldName string) error {
	if val < minVal || val > maxVal {
		return fmt.Errorf("%w: %s must be between %d and %d (got %d)", ErrNumberOutOfRange, fieldName, minVal, maxVal, val)
	}
	return nil
}
