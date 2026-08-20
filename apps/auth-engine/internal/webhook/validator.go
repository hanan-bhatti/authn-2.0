/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/validator.go
 * Tier: Business & Security Validation Layer
 *
 * Validates webhook endpoint registrations: the destination URL and the set of
 * events subscribed to.
 *
 * Both checks run before an endpoint is stored, so a registration that would
 * never deliver is refused at the point the operator can still see why.
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
	// ErrInvalidURL means the destination is empty, unparseable, or uses a
	// scheme not permitted for its host.
	ErrInvalidURL = errors.New("invalid webhook URL: must be a valid HTTPS URL or localhost for development")
	// ErrInvalidEvents means no usable event type was supplied.
	ErrInvalidEvents = errors.New("invalid events: at least one valid subscribed event type is required")
	// ErrUnsupportedEvent means an event name is not one the engine emits.
	ErrUnsupportedEvent = errors.New("unsupported event type provided")
	// ErrEnvironmentRequired means a registration did not state which
	// environment's events it wants. There is no default: see
	// ValidateEndpointEnvironment.
	ErrEnvironmentRequired = errors.New("environment is required")
	// ErrInvalidEnvironment means the environment named is not one of test, live
	// or all.
	ErrInvalidEnvironment = errors.New("invalid environment")
	// ErrEndpointNotFound means no endpoint with that ID exists in the tenant.
	ErrEndpointNotFound = errors.New("webhook endpoint not found")
	// ErrEndpointDisabled means the endpoint exists but is not accepting
	// deliveries.
	ErrEndpointDisabled = errors.New("webhook endpoint is disabled")
	// ErrDeliveryNotFound means no delivery record has that ID.
	ErrDeliveryNotFound = errors.New("webhook delivery record not found")
	// ErrSecretCollision means secret generation produced an already-stored
	// value on every attempt. With 192 bits of entropy this does not occur by
	// chance, so it indicates a broken random source rather than bad luck, and
	// registration is abandoned rather than retried further.
	ErrSecretCollision = errors.New("webhook secret collision detected; generation aborted")
)

// AllowedEventTypes is the set of event names an endpoint may subscribe to.
//
// Subscriptions are checked against this allowlist so that a typo is refused at
// registration instead of producing an endpoint that silently never fires.
var AllowedEventTypes = map[string]bool{
	// Subscribes to every event, including ones added later.
	"*":                         true,
	"user.created":              true,
	"user.signup":               true,
	"user.updated":              true,
	"user.login.success":        true,
	"user.login.failed":         true,
	"user.deleted":              true,
	"session.revoked":           true,
	"2fa.enabled":               true,
	"2fa.disabled":              true,
	"password.changed":          true,
	"rbac.role.assigned":        true,
	"rbac.role.revoked":         true,
	"user.impersonated":         true,
	"user.impersonation_exited": true,
	"org.created":               true,
	"org.updated":               true,
	"org.deleted":               true,
	"org.member_joined":         true,
	"org.member_removed":        true,
	"org.invitation_sent":       true,
	"org.invitation_revoked":    true,
	"org.invitation_accepted":   true,
	"saml.connection_created":   true,
	"saml.connection_updated":   true,
	"saml.connection_deleted":   true,
	"saml.login_success":        true,
	// Delivered only by an explicit test ping, never by system activity.
	"ping": true,
}

// AllowedEnvironments is the set of environments an endpoint may be registered
// for.
//
// "all" is a single endpoint that receives both environments, for a subscriber
// that would rather branch on the payload than run two receivers. It is opt-in
// precisely because the safe reading of a webhook URL is that it belongs to one
// environment.
var AllowedEnvironments = map[string]bool{
	"test": true,
	"live": true,
	"all":  true,
}

// ValidateEndpointEnvironment normalises the environment an endpoint is
// registered for.
//
// The value decides which events reach the destination, so it is not defaulted.
// A default in either direction is a wrong answer an operator cannot see: bias
// towards test and the production integration they just configured receives
// nothing, bias towards live and their sandbox testing is delivered to real
// customers' systems. Refusing costs one round trip and is unambiguous.
//
// Returns ErrEnvironmentRequired when the value is absent and
// ErrInvalidEnvironment, naming the offender, when it is not one of the three.
func ValidateEndpointEnvironment(environment string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(environment))
	if normalized == "" {
		return "", ErrEnvironmentRequired
	}

	if !AllowedEnvironments[normalized] {
		return "", fmt.Errorf("%w: '%s'", ErrInvalidEnvironment, normalized)
	}

	return normalized, nil
}

// ValidateWebhookURL checks that a destination is a usable absolute URL and
// that its scheme is permitted for its host.
//
// HTTPS is accepted for any host. Plain HTTP is accepted only for localhost,
// 127.0.0.1, and hosts under .local, which exist so a developer can point an
// endpoint at a receiver on their own machine. Payloads are signed but not
// encrypted, so cleartext delivery exposes event contents — user identifiers
// and account activity — to anyone on the path.
//
// The rule keys on hostname rather than deployment tier, so the same exception
// applies in production. A .local host in particular is a routable name inside
// many corporate networks rather than a purely local one.
//
// This is a transport check, not an egress one. It accepts any HTTPS host,
// including private ranges and cloud metadata addresses, so it does not
// constrain where the dispatcher connects.
//
// Returns ErrInvalidURL, wrapped with the reason, for an empty or unparseable
// URL, a scheme other than http or https, or plain HTTP to a non-local host.
func ValidateWebhookURL(rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		return ErrInvalidURL
	}

	// ParseRequestURI, unlike Parse, requires an absolute URL, so a bare host
	// or a relative path is rejected here rather than becoming an unroutable
	// endpoint.
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}

	// Hostname strips any port, so the comparison is against the host alone and
	// "localhost:3000" matches.
	host := strings.ToLower(u.Hostname())
	if scheme == "http" && host != "localhost" && host != "127.0.0.1" && !strings.HasSuffix(host, ".local") {
		return fmt.Errorf("%w: http scheme is only allowed for local hosts (localhost/127.0.0.1)", ErrInvalidURL)
	}

	return nil
}

// ValidateSubscribedEvents normalises a subscription list and returns it
// deduplicated.
//
// Names are lowercased and trimmed, blank entries dropped, and duplicates
// removed while preserving the caller's order. The returned slice is what
// should be stored: matching at delivery time is exact, so an unnormalised
// value would never fire.
//
// Returns ErrInvalidEvents when the list is empty or contains nothing but blank
// entries, and ErrUnsupportedEvent naming the offender when a name is not
// recognised. One bad name fails the whole list rather than being skipped,
// since silently dropping it would leave the operator believing they had
// subscribed.
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
