/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/repository.go
 * Tier: Data Access Layer
 *
 * Description: Ent ORM operations for WebhookEndpoint and WebhookEvent entities.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package webhook

import (
	"context"
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/webhookendpoint"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/webhookevent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

type Repository struct {
	factory *clientfactory.ClientFactory
}

func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// IsSecretHashExists checks if a secret hash already exists in the database to prevent collisions.
func (r *Repository) IsSecretHashExists(ctx context.Context, secretHash string) (bool, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.WebhookEndpoint.Query().
		Where(webhookendpoint.SecretKeyHash(secretHash)).
		Exist(ctx)
}

// CreateEndpoint registers a new WebhookEndpoint in Ent ORM.
func (r *Repository) CreateEndpoint(ctx context.Context, tenantID, environment, rawURL, description, encryptedSecret, secretHash string, events []string) (*ent.WebhookEndpoint, error) {
	client := r.factory.GetClient(ctx, tenantID, "")

	id := idgen.New("whe")

	return client.WebhookEndpoint.Create().
		SetID(id).
		SetTenantID(tenantID).
		SetEnvironment(webhookendpoint.Environment(environment)).
		SetURL(rawURL).
		SetDescription(description).
		SetSecretKeyEncrypted(encryptedSecret).
		SetSecretKeyHash(secretHash).
		SetSubscribedEvents(events).
		SetIsActive(true).
		SetFailureCount(0).
		Save(ctx)
}

// GetEndpointByID retrieves a specific webhook endpoint by ID within tenant context.
func (r *Repository) GetEndpointByID(ctx context.Context, tenantID, endpointID string) (*ent.WebhookEndpoint, error) {
	client := r.factory.GetClient(ctx, tenantID, "")
	ep, err := client.WebhookEndpoint.Query().
		Where(webhookendpoint.ID(endpointID), webhookendpoint.TenantID(tenantID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrEndpointNotFound
		}
		return nil, err
	}
	return ep, nil
}

// ListEndpoints retrieves all webhook endpoints for a tenant.
func (r *Repository) ListEndpoints(ctx context.Context, tenantID string) ([]*ent.WebhookEndpoint, error) {
	client := r.factory.GetClient(ctx, tenantID, "")
	return client.WebhookEndpoint.Query().
		Where(webhookendpoint.TenantID(tenantID)).
		Order(ent.Desc(webhookendpoint.FieldCreatedAt)).
		All(ctx)
}

// GetActiveEndpointsForEvent retrieves the active endpoints that should receive
// one event: those registered for its environment or for both, and subscribed
// either to its type or to the wildcard '*'.
//
// The environment predicate is what keeps sandbox activity out of a production
// subscriber's system. It is expressed here rather than left to the privacy
// interceptor because the interceptor narrows a query to one environment, which
// would exclude the endpoints registered for both.
func (r *Repository) GetActiveEndpointsForEvent(ctx context.Context, tenantID, environment, eventType string) ([]*ent.WebhookEndpoint, error) {
	client := r.factory.GetClient(ctx, tenantID, "")
	endpoints, err := client.WebhookEndpoint.Query().
		Where(
			webhookendpoint.TenantID(tenantID),
			webhookendpoint.IsActive(true),
			webhookendpoint.EnvironmentIn(
				webhookendpoint.Environment(environment),
				webhookendpoint.EnvironmentAll,
			),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// Subscription matching stays in Go: subscribed_events is a JSON array, and
	// the predicate that would search it inside the database differs per dialect.
	matching := make([]*ent.WebhookEndpoint, 0)
	for _, ep := range endpoints {
		for _, ev := range ep.SubscribedEvents {
			if ev == "*" || ev == eventType {
				matching = append(matching, ep)
				break
			}
		}
	}
	return matching, nil
}

// UpdateEndpoint modifies an existing webhook endpoint.
func (r *Repository) UpdateEndpoint(ctx context.Context, tenantID, endpointID, environment, rawURL, description string, events []string, isActive *bool) (*ent.WebhookEndpoint, error) {
	// 1. Verify endpoint exists and belongs to tenant
	_, err := r.GetEndpointByID(ctx, tenantID, endpointID)
	if err != nil {
		return nil, err
	}

	client := r.factory.GetClient(ctx, tenantID, "")
	builder := client.WebhookEndpoint.UpdateOneID(endpointID)
	if environment != "" {
		builder.SetEnvironment(webhookendpoint.Environment(environment))
	}
	if rawURL != "" {
		builder.SetURL(rawURL)
	}
	if description != "" {
		builder.SetDescription(description)
	}
	if len(events) > 0 {
		builder.SetSubscribedEvents(events)
	}
	if isActive != nil {
		builder.SetIsActive(*isActive)
	}

	ep, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrEndpointNotFound
		}
		return nil, err
	}
	return ep, nil
}

// RotateEndpointSecret updates the secret key for a webhook endpoint.
func (r *Repository) RotateEndpointSecret(ctx context.Context, tenantID, endpointID, encryptedSecret, secretHash string) (*ent.WebhookEndpoint, error) {
	// 1. Verify endpoint exists and belongs to tenant
	_, err := r.GetEndpointByID(ctx, tenantID, endpointID)
	if err != nil {
		return nil, err
	}

	client := r.factory.GetClient(ctx, tenantID, "")
	ep, err := client.WebhookEndpoint.UpdateOneID(endpointID).
		SetSecretKeyEncrypted(encryptedSecret).
		SetSecretKeyHash(secretHash).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrEndpointNotFound
		}
		return nil, err
	}
	return ep, nil
}

// DeleteEndpoint removes a webhook endpoint and automatically cleans up child events using Ent ORM under normal request context.
func (r *Repository) DeleteEndpoint(ctx context.Context, tenantID, endpointID string) error {
	// 1. Verify endpoint exists and belongs to tenant
	_, err := r.GetEndpointByID(ctx, tenantID, endpointID)
	if err != nil {
		return err
	}

	client := r.factory.GetClient(ctx, tenantID, "")
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 2. Delete associated child delivery logs using Ent ORM
	_, err = tx.WebhookEvent.Delete().
		Where(webhookevent.WebhookEndpointID(endpointID)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed deleting webhook delivery logs: %w", err)
	}

	// 3. Delete parent webhook endpoint using Ent ORM
	err = tx.WebhookEndpoint.DeleteOneID(endpointID).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrEndpointNotFound
		}
		return err
	}

	return tx.Commit()
}

// CreateDelivery logs an HTTP webhook dispatch attempt in Ent ORM.
func (r *Repository) CreateDelivery(ctx context.Context, endpointID, eventType string, payload map[string]interface{}, statusCode int, responseBody, errorMessage string, isSuccess bool) (*ent.WebhookEvent, error) {
	client := r.factory.GetClient(ctx, "", "")

	id := idgen.New("whd")

	statusVal := webhookevent.StatusFailed
	if isSuccess {
		statusVal = webhookevent.StatusSuccess
	}

	return client.WebhookEvent.Create().
		SetID(id).
		SetWebhookEndpointID(endpointID).
		SetEventType(eventType).
		SetPayload(payload).
		SetStatusCode(statusCode).
		SetResponseBody(responseBody).
		SetErrorMessage(errorMessage).
		SetStatus(statusVal).
		Save(ctx)
}

// ListDeliveries retrieves delivery log history for an endpoint or event type.
func (r *Repository) ListDeliveries(ctx context.Context, endpointID, eventType string, limit int) ([]*ent.WebhookEvent, error) {
	client := r.factory.GetClient(ctx, "", "")

	query := client.WebhookEvent.Query()
	if endpointID != "" {
		query.Where(webhookevent.WebhookEndpointID(endpointID))
	}
	if eventType != "" {
		query.Where(webhookevent.EventType(eventType))
	}

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	return query.
		Order(ent.Desc(webhookevent.FieldCreatedAt)).
		Limit(limit).
		All(ctx)
}

// GetDeliveryByID retrieves a specific delivery log record.
func (r *Repository) GetDeliveryByID(ctx context.Context, deliveryID string) (*ent.WebhookEvent, error) {
	client := r.factory.GetClient(ctx, "", "")
	ev, err := client.WebhookEvent.Query().
		Where(webhookevent.ID(deliveryID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrDeliveryNotFound
		}
		return nil, err
	}
	return ev, nil
}
