/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/validator.go
 * Tier: Business & Security Validation Layer
 *
 * Description: Input validation and editability checks for webhook endpoint
 *              registrations, URL schemas, and subscribed event categories.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package webhook

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrInvalidURL          = errors.New("invalid webhook URL: must be a valid HTTPS URL or localhost for development")
	ErrInvalidEvents       = errors.New("invalid events: at least one valid subscribed event type is required")
	ErrUnsupportedEvent    = errors.New("unsupported event type provided")
	ErrEndpointNotFound    = errors.New("webhook endpoint not found")
	ErrEndpointDisabled    = errors.New("webhook endpoint is disabled")
	ErrDeliveryNotFound    = errors.New("webhook delivery record not found")
	ErrSecretCollision     = errors.New("webhook secret collision detected; generation aborted")
)

// AllowedEventTypes contains all valid system event categories supported by Authn Engine webhooks.
var AllowedEventTypes = map[string]bool{
	"*":                    true, // Wildcard (all events)
	"user.created":         true,
	"user.signup":          true,
	"user.login.success":   true,
	"user.login.failed":    true,
	"user.deleted":         true,
	"session.revoked":      true,
	"2fa.enabled":          true,
	"2fa.disabled":         true,
	"password.changed":     true,
	"rbac.role.assigned":   true,
	"rbac.role.revoked":    true,
	"ping":                 true,
}

// ValidateWebhookURL validates that the target URL is well-formed.
// HTTPS is required for external hosts; HTTP is permitted for local development (localhost / 127.0.0.1).
func ValidateWebhookURL(rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		return ErrInvalidURL
	}

	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}

	host := strings.ToLower(u.Hostname())
	if scheme == "http" && host != "localhost" && host != "127.0.0.1" && !strings.HasSuffix(host, ".local") {
		return fmt.Errorf("%w: http scheme is only allowed for local hosts (localhost/127.0.0.1)", ErrInvalidURL)
	}

	return nil
}

// ValidateSubscribedEvents checks that the events slice is non-empty and contains only valid event types.
func ValidateSubscribedEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, ErrInvalidEvents
	}

	cleaned := make([]string, 0, len(events))
	seen := make(map[string]bool)

	for _, ev := range events {
		trimmed := strings.ToLower(strings.TrimSpace(ev))
		if trimmed == "" {
			continue
		}

		if !AllowedEventTypes[trimmed] {
			return nil, fmt.Errorf("%w: '%s'", ErrUnsupportedEvent, trimmed)
		}

		if !seen[trimmed] {
			seen[trimmed] = true
			cleaned = append(cleaned, trimmed)
		}
	}

	if len(cleaned) == 0 {
		return nil, ErrInvalidEvents
	}

	return cleaned, nil
}
