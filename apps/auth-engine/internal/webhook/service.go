/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/service.go
 * Tier: Business Logic Service Layer
 *
 * Endpoint lifecycle: registration, updates, secret rotation, deletion, and the
 * operator-facing delivery history.
 *
 * The signing secret is the sensitive value here. It is generated, shown to the
 * operator exactly once, and stored encrypted; nothing can read it back
 * afterwards. An operator who loses it rotates rather than recovers, which is
 * why RotateSecret exists at all.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package webhook

import (
	"context"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
)

// secretGenerationAttempts bounds how many times a colliding secret is
// regenerated before registration is abandoned. A collision across 192 bits of
// entropy does not happen by chance, so exhausting these attempts means the
// random source is broken, and retrying further would not help.
const secretGenerationAttempts = 3

// Service coordinates endpoint management.
type Service struct {
	// repo persists endpoints and delivery records.
	repo *Repository
	// dispatcher performs the synchronous deliveries behind test pings and
	// redeliveries.
	dispatcher *Dispatcher
	// cfg supplies the encryption key protecting stored secrets.
	cfg *config.Config
}

// NewService constructs the endpoint management service.
func NewService(repo *Repository, dispatcher *Dispatcher, cfg *config.Config) *Service {
	return &Service{
		repo:       repo,
		dispatcher: dispatcher,
		cfg:        cfg,
	}
}

// CreateEndpointRequest is the body of an endpoint registration.
type CreateEndpointRequest struct {
	// URL is the destination. It must satisfy ValidateWebhookURL.
	URL string `json:"url"`
	// Description is an operator-facing label.
	Description string `json:"description"`
	// Events lists the event types to subscribe to.
	Events []string `json:"events"`
}

// UpdateEndpointRequest is the body of an endpoint update. Empty fields leave
// the stored value unchanged, so a caller may send only what it is changing.
type UpdateEndpointRequest struct {
	// URL replaces the destination when non-empty.
	URL string `json:"url"`
	// Description replaces the label when non-empty.
	Description string `json:"description"`
	// Events replaces the subscription list when non-empty.
	Events []string `json:"events"`
	// IsActive enables or disables delivery. It is a pointer so that an omitted
	// field is distinguishable from an explicit false, which would otherwise
	// silently disable the endpoint on every partial update.
	IsActive *bool `json:"is_active"`
}

// EndpointResponse is the operator-facing view of an endpoint.
type EndpointResponse struct {
	// ID identifies the endpoint.
	ID string `json:"id"`
	// URL is the delivery destination.
	URL string `json:"url"`
	// Description is the operator-facing label.
	Description string `json:"description"`
	// Secret is the signing secret, present only in the response to creation or
	// rotation. It is omitted everywhere else because it cannot be read back.
	Secret string `json:"secret,omitempty"`
	// SubscribedEvents is the normalised subscription list.
	SubscribedEvents []string `json:"subscribed_events"`
	// IsActive reports whether deliveries are being attempted.
	IsActive bool `json:"is_active"`
	// FailureCount is the recorded consecutive failure tally.
	FailureCount int `json:"failure_count"`
	// LastTriggeredAt is the most recent delivery attempt in RFC 3339, omitted
	// when the endpoint has never fired.
	LastTriggeredAt *string `json:"last_triggered_at,omitempty"`
	// CreatedAt is the registration time in RFC 3339.
	CreatedAt string `json:"created_at"`
}

// DeliveryResponse is the operator-facing view of one delivery attempt.
type DeliveryResponse struct {
	// ID identifies the delivery record.
	ID string `json:"id"`
	// EndpointID is the endpoint it was sent to.
	EndpointID string `json:"endpoint_id"`
	// EventType is the event that triggered it.
	EventType string `json:"event_type"`
	// Payload is the body that was sent, retained so the delivery can be
	// inspected and replayed.
	Payload map[string]interface{} `json:"payload"`
	// StatusCode is the HTTP status returned, zero when the request never
	// completed.
	StatusCode int `json:"status_code"`
	// ResponseBody is the truncated response, kept for diagnosis.
	ResponseBody string `json:"response_body"`
	// ErrorMessage describes the failure, empty on success.
	ErrorMessage string `json:"error_message"`
	// Status is the outcome, "success" or "failed".
	Status string `json:"status"`
	// CreatedAt is the attempt time in RFC 3339.
	CreatedAt string `json:"created_at"`
}

// CreateEndpoint registers an endpoint and returns it with its newly generated
// signing secret.
//
// The returned Secret is the only time that value is available; it is stored
// encrypted and cannot be retrieved afterwards.
//
// Returns ErrInvalidURL or an event validation error for a bad request,
// ErrSecretCollision when secret generation cannot produce an unused value, and
// an error if encryption or persistence fails.
func (s *Service) CreateEndpoint(ctx context.Context, tenantID string, req CreateEndpointRequest) (*EndpointResponse, error) {
	if err := ValidateWebhookURL(req.URL); err != nil {
		return nil, err
	}

	events, err := ValidateSubscribedEvents(req.Events)
	if err != nil {
		return nil, err
	}

	// Generate until an unused secret appears. The uniqueness index is what
	// makes a secret usable as an endpoint's sole proof of origin.
	var rawSecret, secretHash string
	for attempt := 0; attempt < secretGenerationAttempts; attempt++ {
		sec, err := GenerateSecretKey()
		if err != nil {
			return nil, err
		}
		hash := HashSecret(sec)

		exists, err := s.repo.IsSecretHashExists(ctx, hash)
		if err != nil {
			return nil, err
		}
		if !exists {
			rawSecret = sec
			secretHash = hash
			break
		}
	}

	if rawSecret == "" {
		return nil, ErrSecretCollision
	}

	// Encrypt before storing: the dispatcher needs the secret back to sign
	// payloads, so it cannot be hashed the way a password would be.
	encryptedSecret, err := crypto.EncryptAES256GCM(rawSecret, s.cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt webhook secret: %w", err)
	}

	ep, err := s.repo.CreateEndpoint(ctx, tenantID, req.URL, req.Description, encryptedSecret, secretHash, events)
	if err != nil {
		return nil, err
	}

	resp := formatEndpointResponse(ep)
	// The only point at which the secret leaves this process.
	resp.Secret = rawSecret
	return resp, nil
}

// ListEndpoints returns every endpoint registered by a tenant.
//
// Secrets are absent from the results, since they cannot be read back.
// Returns an error if the query fails.
func (s *Service) ListEndpoints(ctx context.Context, tenantID string) ([]EndpointResponse, error) {
	endpoints, err := s.repo.ListEndpoints(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	resps := make([]EndpointResponse, len(endpoints))
	for i, ep := range endpoints {
		resps[i] = *formatEndpointResponse(ep)
	}
	return resps, nil
}

// GetEndpoint retrieves details for a single endpoint.
func (s *Service) GetEndpoint(ctx context.Context, tenantID, endpointID string) (*EndpointResponse, error) {
	ep, err := s.repo.GetEndpointByID(ctx, tenantID, endpointID)
	if err != nil {
		return nil, err
	}
	return formatEndpointResponse(ep), nil
}

// UpdateEndpoint modifies an endpoint configuration.
func (s *Service) UpdateEndpoint(ctx context.Context, tenantID, endpointID string, req UpdateEndpointRequest) (*EndpointResponse, error) {
	if req.URL != "" {
		if err := ValidateWebhookURL(req.URL); err != nil {
			return nil, err
		}
	}

	var events []string
	var err error
	if len(req.Events) > 0 {
		events, err = ValidateSubscribedEvents(req.Events)
		if err != nil {
			return nil, err
		}
	}

	ep, err := s.repo.UpdateEndpoint(ctx, tenantID, endpointID, req.URL, req.Description, events, req.IsActive)
	if err != nil {
		return nil, err
	}
	return formatEndpointResponse(ep), nil
}

// RotateSecret generates a fresh whsec_ secret key for an endpoint.
func (s *Service) RotateSecret(ctx context.Context, tenantID, endpointID string) (*EndpointResponse, error) {
	// Verify endpoint exists
	_, err := s.repo.GetEndpointByID(ctx, tenantID, endpointID)
	if err != nil {
		return nil, err
	}

	var rawSecret, secretHash string
	for attempt := 0; attempt < 3; attempt++ {
		sec, err := GenerateSecretKey()
		if err != nil {
			return nil, err
		}
		hash := HashSecret(sec)

		exists, err := s.repo.IsSecretHashExists(ctx, hash)
		if err != nil {
			return nil, err
		}
		if !exists {
			rawSecret = sec
			secretHash = hash
			break
		}
	}

	if rawSecret == "" {
		return nil, ErrSecretCollision
	}

	encryptedSecret, err := crypto.EncryptAES256GCM(rawSecret, s.cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt new webhook secret: %w", err)
	}

	ep, err := s.repo.RotateEndpointSecret(ctx, tenantID, endpointID, encryptedSecret, secretHash)
	if err != nil {
		return nil, err
	}

	resp := formatEndpointResponse(ep)
	resp.Secret = rawSecret // Return newly rotated secret ONCE
	return resp, nil
}

// DeleteEndpoint removes a webhook endpoint.
func (s *Service) DeleteEndpoint(ctx context.Context, tenantID, endpointID string) error {
	return s.repo.DeleteEndpoint(ctx, tenantID, endpointID)
}

// SendTestPing dispatches a test 'ping' event synchronously to an endpoint.
func (s *Service) SendTestPing(ctx context.Context, tenantID, endpointID string) (*DeliveryResponse, error) {
	ep, err := s.repo.GetEndpointByID(ctx, tenantID, endpointID)
	if err != nil {
		return nil, err
	}

	pingData := map[string]interface{}{
		"message":  "This is a test ping event from Authn Engine to verify HMAC signature verification.",
		"sent_at":  time.Now().Format(time.RFC3339),
		"endpoint": ep.URL,
	}

	ev, err := s.dispatcher.DeliverSync(ctx, ep, "ping", pingData)
	if err != nil {
		return nil, err
	}

	return formatDeliveryResponse(ev), nil
}

// ListDeliveries retrieves delivery log history.
func (s *Service) ListDeliveries(ctx context.Context, endpointID, eventType string, limit int) ([]DeliveryResponse, error) {
	deliveries, err := s.repo.ListDeliveries(ctx, endpointID, eventType, limit)
	if err != nil {
		return nil, err
	}

	resps := make([]DeliveryResponse, len(deliveries))
	for i, d := range deliveries {
		resps[i] = *formatDeliveryResponse(d)
	}
	return resps, nil
}

// Redeliver re-triggers a delivery attempt for a past event.
func (s *Service) Redeliver(ctx context.Context, tenantID, deliveryID string) (*DeliveryResponse, error) {
	ev, err := s.repo.GetDeliveryByID(ctx, deliveryID)
	if err != nil {
		return nil, err
	}

	ep, err := s.repo.GetEndpointByID(ctx, tenantID, ev.WebhookEndpointID)
	if err != nil {
		return nil, err
	}

	newEv, err := s.dispatcher.DeliverSync(ctx, ep, ev.EventType, ev.Payload)
	if err != nil {
		return nil, err
	}

	return formatDeliveryResponse(newEv), nil
}

func formatEndpointResponse(ep *ent.WebhookEndpoint) *EndpointResponse {
	var lastTriggered *string
	if ep.LastTriggeredAt != nil {
		formatted := ep.LastTriggeredAt.Format(time.RFC3339)
		lastTriggered = &formatted
	}

	return &EndpointResponse{
		ID:               ep.ID,
		URL:              ep.URL,
		Description:      ep.Description,
		SubscribedEvents: ep.SubscribedEvents,
		IsActive:         ep.IsActive,
		FailureCount:     ep.FailureCount,
		LastTriggeredAt:  lastTriggered,
		CreatedAt:        ep.CreatedAt.Format(time.RFC3339),
	}
}

func formatDeliveryResponse(d *ent.WebhookEvent) *DeliveryResponse {
	return &DeliveryResponse{
		ID:           d.ID,
		EndpointID:   d.WebhookEndpointID,
		EventType:    d.EventType,
		Payload:      d.Payload,
		StatusCode:   d.StatusCode,
		ResponseBody: d.ResponseBody,
		ErrorMessage: d.ErrorMessage,
		Status:       string(d.Status),
		CreatedAt:    d.CreatedAt.Format(time.RFC3339),
	}
}
