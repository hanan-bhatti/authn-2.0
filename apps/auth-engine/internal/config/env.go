/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/config/env.go
 * Tier: Configuration Layer
 *
 * Typed environment-variable readers.
 *
 * Every reader follows the same contract:
 *
 *   - variable unset or empty  -> the caller's fallback is used, no error
 *   - variable set and valid   -> the parsed value is used
 *   - variable set but invalid -> the fallback is used AND an error is recorded
 *
 * That last case is the important one. Silently ignoring a malformed value means
 * a typo such as PORT=80o0 boots the server on the default port and nobody finds
 * out until traffic goes missing. Recording the error lets Load report every
 * problem at once and refuse to start.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// envReader reads and parses environment variables, accumulating a list of
// problems rather than failing on the first one. Collecting all errors means an
// operator fixes one deployment config in a single pass instead of restarting
// the server once per mistake.
//
// The zero value is ready to use.
type envReader struct {
	// problems holds one human-readable message per invalid or missing variable.
	problems []string
}

// fail records a configuration problem. Load turns a non-empty list into a
// startup error.
func (r *envReader) fail(format string, args ...any) {
	r.problems = append(r.problems, fmt.Sprintf(format, args...))
}

// err returns a single error describing every problem found, or nil when the
// configuration is valid.
func (r *envReader) err() error {
	if len(r.problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(r.problems, "\n  - "))
}

// lookup returns the trimmed value of key and whether it was set to a non-empty
// string. Surrounding quotes are removed so both FOO=bar and FOO="bar" work.
func lookup(key string) (string, bool) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	val := strings.TrimSpace(raw)
	val = strings.Trim(val, `"'`)
	if val == "" {
		return "", false
	}
	return val, true
}

// str returns a string variable, or fallback when unset.
func (r *envReader) str(key, fallback string) string {
	if val, ok := lookup(key); ok {
		return val
	}
	return fallback
}

// required returns a string variable and records a problem when it is missing.
// Use for values that have no safe default, such as credentials.
func (r *envReader) required(key string) string {
	val, ok := lookup(key)
	if !ok {
		r.fail("%s is required but not set", key)
		return ""
	}
	return val
}

// requiredMinLen returns a string variable that must also meet a minimum length.
// Used for cryptographic secrets, where a short value is as dangerous as a
// missing one because it still lets the process boot.
func (r *envReader) requiredMinLen(key string, minLen int) string {
	val, ok := lookup(key)
	if !ok {
		r.fail("%s is required but not set (minimum %d characters)", key, minLen)
		return ""
	}
	if len(val) < minLen {
		r.fail("%s must be at least %d characters, got %d", key, minLen, len(val))
	}
	return val
}

// integer returns an int variable, or fallback when unset or unparseable.
func (r *envReader) integer(key string, fallback int) int {
	val, ok := lookup(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		r.fail("%s must be a whole number, got %q", key, val)
		return fallback
	}
	return parsed
}

// port returns a TCP port number, rejecting values outside 1-65535.
//
// Port 0 is excluded deliberately: the operating system reads it as "any free
// port", which would start the server somewhere unpredictable.
func (r *envReader) port(key string, fallback int) int {
	val := r.integer(key, fallback)
	if val < 1 || val > 65535 {
		r.fail("%s must be a port between 1 and 65535, got %d", key, val)
		return fallback
	}
	return val
}

// positive returns an int that must be greater than zero. Used for sizes,
// counts, and limits where zero or negative would disable a protection.
func (r *envReader) positive(key string, fallback int) int {
	val := r.integer(key, fallback)
	if val <= 0 {
		r.fail("%s must be greater than 0, got %d", key, val)
		return fallback
	}
	return val
}

// boolean returns a bool variable. Accepts the forms strconv.ParseBool does:
// 1, t, T, TRUE, true, True and their false counterparts.
func (r *envReader) boolean(key string, fallback bool) bool {
	val, ok := lookup(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		r.fail("%s must be true or false, got %q", key, val)
		return fallback
	}
	return parsed
}

// duration returns a duration variable written in Go's duration syntax
// ("30s", "15m", "24h", "720h"). Durations must be positive: a zero TTL would
// mean a token that is expired the instant it is issued.
func (r *envReader) duration(key string, fallback time.Duration) time.Duration {
	val, ok := lookup(key)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(val)
	if err != nil {
		r.fail("%s must be a duration such as 30s, 15m or 24h, got %q", key, val)
		return fallback
	}
	if parsed <= 0 {
		r.fail("%s must be a positive duration, got %q", key, val)
		return fallback
	}
	return parsed
}

// durationList returns a comma-separated list of durations, used for the
// rate-limiter's escalating lockout schedule ("15m,1h,6h,24h").
func (r *envReader) durationList(key string, fallback []time.Duration) []time.Duration {
	val, ok := lookup(key)
	if !ok {
		return fallback
	}
	parts := strings.Split(val, ",")
	out := make([]time.Duration, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsed, err := time.ParseDuration(part)
		if err != nil || parsed <= 0 {
			r.fail("%s must be a comma-separated list of positive durations such as 15m,1h,6h — %q is not valid", key, part)
			return fallback
		}
		out = append(out, parsed)
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

// list returns a comma-separated list of strings with blank entries removed.
func (r *envReader) list(key string, fallback []string) []string {
	val, ok := lookup(key)
	if !ok {
		return fallback
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

// absoluteURL returns a URL variable that must be absolute and http(s).
//
// A relative or scheme-less value here is a common and damaging mistake: this
// URL is used to build links sent to users and redirect targets, so a bad value
// produces broken emails or a redirect that leaves the application's origin.
// Any trailing slash is removed so callers can concatenate paths safely.
func (r *envReader) absoluteURL(key, fallback string) string {
	val, ok := lookup(key)
	if !ok {
		return strings.TrimRight(fallback, "/")
	}
	parsed, err := url.Parse(val)
	if err != nil {
		r.fail("%s must be a valid URL, got %q", key, val)
		return strings.TrimRight(fallback, "/")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		r.fail("%s must start with http:// or https://, got %q", key, val)
		return strings.TrimRight(fallback, "/")
	}
	if parsed.Host == "" {
		r.fail("%s must include a host, got %q", key, val)
		return strings.TrimRight(fallback, "/")
	}
	return strings.TrimRight(val, "/")
}

// originList returns a list of browser origins (scheme + host + optional port,
// with no path), used for the CORS allowlist.
//
// The literal "*" is accepted and returned as-is; Validate decides whether a
// wildcard is permissible, because that depends on whether credentialed
// requests are enabled.
func (r *envReader) originList(key string, fallback []string) []string {
	values := r.list(key, fallback)
	for _, origin := range values {
		if origin == "*" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			r.fail("%s entries must be full origins such as https://app.example.com, got %q", key, origin)
			continue
		}
		if parsed.Path != "" && parsed.Path != "/" {
			r.fail("%s entries must not include a path, got %q", key, origin)
		}
	}
	return values
}

// oneOf returns a string variable constrained to a fixed set of choices, such
// as the email driver name. Listing the valid options in the error message
// turns a silent misconfiguration into an immediately actionable one.
func (r *envReader) oneOf(key, fallback string, allowed ...string) string {
	val := strings.ToLower(r.str(key, fallback))
	for _, choice := range allowed {
		if val == choice {
			return val
		}
	}
	r.fail("%s must be one of [%s], got %q", key, strings.Join(allowed, ", "), val)
	return fallback
}
