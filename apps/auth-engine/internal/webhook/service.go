/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/service.go
 * Tier: Business Logic Service Layer
 *
 * Description: Webhook management service coordinating validation, secret key generation,
 *              AES-256-GCM encryption, collision checking, and dispatching.
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

type Service struct {
	repo       *Repository
	dispatcher *Dispatcher
	cfg        *config.Config
}

func NewService(repo *Repository, dispatcher *Dispatcher, cfg *config.Config) *Service {
	return &Service{
		repo:       repo,
		dispatcher: dispatcher,
		cfg:        cfg,
	}
}

type CreateEndpointRequest struct {
	URL         string   `json:"url"`
	Description string   `json:"description"`
	Events      []string `json:"events"`
}

type UpdateEndpointRequest struct {
	URL         string   `json:"url"`
	Description string   `json:"description"`
	Events      []string `json:"events"`
	IsActive    *bool    `json:"is_active"`
}

type EndpointResponse struct {
	ID                string    `json:"id"`
	URL               string    `json:"url"`
	Description       string    `json:"description"`
	Secret            string    `json:"secret,omitempty"` // Returned ONCE on creation or secret rotation!
	SubscribedEvents  []string  `json:"subscribed_events"`
	IsActive          bool      `json:"is_active"`
	FailureCount      int       `json:"failure_count"`
	LastTriggeredAt   *string   `json:"last_triggered_at,omitempty"`
	CreatedAt         string    `json:"created_at"`
}

type DeliveryResponse struct {
	ID                string                 `json:"id"`
	EndpointID        string                 `json:"endpoint_id"`
	EventType         string                 `json:"event_type"`
	Payload           map[string]interface{} `json:"payload"`
	StatusCode        int                    `json:"status_code"`
	ResponseBody      string                 `json:"response_body"`
	ErrorMessage      string                 `json:"error_message"`
	Status            string                 `json:"status"`
	CreatedAt         string                 `json:"created_at"`
}

// CreateEndpoint registers a new webhook endpoint, generating a unique whsec_ secret key.
func (s *Service) CreateEndpoint(ctx context.Context, tenantID string, req CreateEndpointRequest) (*EndpointResponse, error) {
	if err := ValidateWebhookURL(req.URL); err != nil {
		return nil, err
	}

	events, err := ValidateSubscribedEvents(req.Events)
	if err != nil {
		return nil, err
	}

	// Generate secret key with collision prevention check
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

	// Encrypt secret key at rest with AES-256-GCM
	encryptedSecret, err := crypto.EncryptAES256GCM(rawSecret, s.cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt webhook secret: %w", err)
	}

	ep, err := s.repo.CreateEndpoint(ctx, tenantID, req.URL, req.Description, encryptedSecret, secretHash, events)
	if err != nil {
		return nil, err
	}

	resp := formatEndpointResponse(ep)
	resp.Secret = rawSecret // Include unencrypted secret key in response payload once!
	return resp, nil
}

// ListEndpoints retrieves all endpoints for a tenant.
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
		"message":   "This is a test ping event from Authn Engine to verify HMAC signature verification.",
		"sent_at":   time.Now().Format(time.RFC3339),
		"endpoint":  ep.URL,
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
