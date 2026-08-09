/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/pkg/validator/validator.go
 * Tier: Shared Package / Request Input Validation
 *
 * Validation and normalisation for values that arrive from callers: email
 * addresses, free-text fields, avatar URLs and numeric parameters.
 *
 * These checks reject input at the edge, before it reaches storage or a
 * template. They are a first filter, not the last line of defence — an avatar
 * URL that passes ValidateImageURL is still escaped when rendered, and text
 * that passes SanitizeString is still parameterised when queried. Treating any
 * check here as a substitute for contextual output encoding would make every
 * gap in a pattern an injection.
 *
 * Every function that normalises returns the cleaned value, and callers are
 * expected to store what is returned rather than what they passed in.
 * Persisting the raw input would discard the trimming and scheme resolution
 * that later checks assume has happened.
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
	// ErrInvalidEmail means the address is empty or does not match the accepted
	// syntax.
	ErrInvalidEmail = errors.New("invalid email address format")
	// ErrEmailTooLong means the address exceeds the 254-character limit RFC 5321
	// places on a forward path.
	ErrEmailTooLong = errors.New("email address exceeds maximum length of 254 characters")
	// ErrStringTooShort means a field is below its caller-supplied minimum.
	ErrStringTooShort = errors.New("input string is shorter than required minimum length")
	// ErrStringTooLong means a field is above its caller-supplied maximum.
	ErrStringTooLong = errors.New("input string exceeds maximum permitted length")
	// ErrContainsControlCh means the value contains control characters or a null
	// byte, which are used to truncate strings or forge line breaks in headers
	// and log entries.
	ErrContainsControlCh = errors.New("input contains prohibited control characters or null bytes")
	// ErrXSSDetected means the value matched a script or markup injection
	// pattern.
	ErrXSSDetected = errors.New("input contains prohibited script or HTML injection payload")
	// ErrInvalidImageURL means the value is neither an absolute HTTP(S) URL nor
	// a bare domain path, or resolves to something with no host.
	ErrInvalidImageURL = errors.New("invalid image URL: must be a valid HTTP/HTTPS image URL or domain reference")
	// ErrDisallowedScheme means the URL names a scheme other than http or https.
	// It is returned for javascript:, data:, file:, ftp: and vbscript:, each of
	// which turns a stored URL into code execution or local file access when a
	// browser follows it.
	ErrDisallowedScheme = errors.New("prohibited URI scheme detected (only http:// and https:// are permitted)")
	// ErrNumberOutOfRange means a numeric parameter falls outside its permitted
	// bounds.
	ErrNumberOutOfRange = errors.New("numeric value is outside permitted min/max range")
)

var (
	// emailRegex accepts the practical subset of RFC 5322: unquoted local part,
	// then a dot-separated domain whose labels are 1-63 characters and neither
	// start nor end with a hyphen. Quoted local parts and bracketed IP literals
	// are legal syntax but are refused, since neither survives a round trip
	// through the mail providers this engine delivers through.
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

	// xssRegex matches the markup and scheme fragments that turn stored text
	// into script when it reaches a page. It is a denylist and therefore
	// incomplete by construction; it exists to reject obvious payloads early,
	// and never replaces escaping at the point of output.
	xssRegex = regexp.MustCompile(`(?i)(<script|javascript:|data:text/html|vbscript:|onload=|onerror=|onclick=|<iframe|<object|<embed)`)

	// domainRegex matches a bare host with at least one dot, optionally followed
	// by a path — the "img.example.com/avatar.png" form that users paste
	// without a scheme.
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(/.*)?$`)
)

// ValidateEmail reports whether an address is syntactically usable.
//
// It checks length before syntax so that a pathological input fails on a cheap
// comparison rather than in the regex engine.
//
// Returns ErrInvalidEmail when empty or malformed, ErrEmailTooLong past 254
// characters, or ErrContainsControlCh when the value carries control bytes —
// which in an address are an attempt to inject extra SMTP headers.
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

// ContainsControlChars reports whether s holds a null byte or an unprintable
// control character.
//
// Tab, newline and carriage return are permitted: they are legitimate in
// multi-line fields. Callers that write values into a header or a log line must
// still reject those three themselves, since that is exactly where they let an
// attacker forge a new line.
func ContainsControlChars(s string) bool {
	for _, r := range s {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') || r == 127 {
			return true
		}
	}
	return false
}

// ContainsXSS reports whether s matches a known script injection pattern.
func ContainsXSS(s string) bool {
	return xssRegex.MatchString(s)
}

// SanitizeString trims s and enforces length bounds, rejecting control
// characters and script payloads.
//
// A maxLen of zero means no upper bound. Bounds are measured in bytes, not
// runes, so a limit sized for a display name allows fewer characters of
// non-Latin text than of ASCII.
//
// Returns the trimmed value, or ErrStringTooShort, ErrStringTooLong,
// ErrContainsControlCh or ErrXSSDetected. The returned string is what callers
// should store; the original still carries the surrounding whitespace.
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

// ValidateImageURL checks that an avatar or picture URL is safe to store and to
// place in an href or src, and returns it in absolute form.
//
// An empty input returns ("", nil): having no avatar is valid, and callers
// treat the empty result as "unset" rather than as a failure.
//
// A value with no scheme but a plausible host is resolved to https, so
// "img.example.com/a.png" is stored as "https://img.example.com/a.png".
// Defaulting to https rather than http means a pasted URL is never silently
// downgraded to cleartext.
//
// Returns ErrXSSDetected for control characters or script payloads,
// ErrDisallowedScheme for a non-HTTP(S) scheme, and ErrInvalidImageURL when the
// value is neither absolute nor a recognisable bare domain, or parses with no
// host.
//
// It validates syntax and scheme only. The host is not resolved and no address
// range is excluded, so a caller that fetches or proxies the result — rather
// than handing it to a browser — must apply its own egress restrictions.
func ValidateImageURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", nil
	}

	if ContainsControlChars(rawURL) || ContainsXSS(rawURL) {
		return "", ErrXSSDetected
	}

	// Dangerous schemes are rejected before the value is parsed. url.Parse
	// happily accepts "javascript:alert(1)", and the check that follows only
	// establishes a scheme is present, not that it is safe.
	lower := strings.ToLower(rawURL)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "ftp:") || strings.HasPrefix(lower, "vbscript:") {
		return "", ErrDisallowedScheme
	}

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

	// Constrain the host to characters a hostname or port can contain. This
	// catches markup that survived the earlier pattern check by sitting in the
	// authority, where it would otherwise be written straight into an src.
	for _, r := range u.Host {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != ':' {
			return "", ErrInvalidImageURL
		}
	}

	return targetURL, nil
}

// ValidateIntRange checks that val lies within minVal and maxVal inclusive.
//
// fieldName appears in the error, so a caller validating several parameters
// produces a message naming the one that failed. Returns ErrNumberOutOfRange
// wrapped with the bounds and the offending value.
func ValidateIntRange(val int, minVal, maxVal int, fieldName string) error {
	if val < minVal || val > maxVal {
		return fmt.Errorf("%w: %s must be between %d and %d (got %d)", ErrNumberOutOfRange, fieldName, minVal, maxVal, val)
	}
	return nil
}
