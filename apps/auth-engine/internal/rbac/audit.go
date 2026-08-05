/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/audit.go
 * Tier: Audit Trail & Compliance Layer
 *
 * Description: Audit logger for RBAC security events. Records immutable logs detailing
 *              who created, modified, assigned, or revoked roles and permissions.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package rbac

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// AuditLogger wraps clientfactory.ClientFactory for logging RBAC audit events.
type AuditLogger struct {
	factory *clientfactory.ClientFactory
}

// NewAuditLogger initializes a new AuditLogger instance.
func NewAuditLogger(factory *clientfactory.ClientFactory) *AuditLogger {
	return &AuditLogger{factory: factory}
}

// LogRBACEvent records an immutable audit log entry for RBAC security changes.
func (a *AuditLogger) LogRBACEvent(ctx context.Context, tenantID, actorType, actorID, eventType, targetType, targetID string, metadata map[string]interface{}, ip, userAgent string) error {
	client := a.factory.GetClient(ctx, tenantID, "")

	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["target_type"] = targetType
	if targetID != "" {
		metadata["target_id"] = targetID
		if targetType == "user" {
			metadata["target_user_id"] = targetID
		}
	}

	var actorTypeEnum auditlog.ActorType
	switch actorType {
	case "admin":
		actorTypeEnum = auditlog.ActorTypeAdmin
	case "system":
		actorTypeEnum = auditlog.ActorTypeSystem
	default:
		actorTypeEnum = auditlog.ActorTypeUser
	}

	logID := fmt.Sprintf("log_%s", uuid.New().String()[:12])

	builder := client.AuditLog.Create().
		SetID(logID).
		SetTenantID(tenantID).
		SetActorType(actorTypeEnum).
		SetEventType(eventType).
		SetMetadata(metadata)

	if actorID != "" {
		builder.SetUserID(actorID)
	}
	if ip != "" {
		builder.SetIPAddress(ip)
	}
	if userAgent != "" {
		builder.SetUserAgent(userAgent)
	}

	_, err := builder.Save(ctx)
	return err
}
