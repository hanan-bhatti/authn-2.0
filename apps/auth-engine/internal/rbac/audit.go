/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/rbac/audit.go
 * Tier: Audit Trail & Compliance Layer
 *
 * Audit logging for RBAC security events.
 *
 * Every change to who holds which authority is recorded: role creation and
 * modification, permission updates, and role assignment or revocation. The
 * entries are append-only and carry the actor, the target, and the network
 * context the change arrived from, so an authority change can always be traced
 * to a request.
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

// AuditLogger writes RBAC audit entries through a tenant-scoped ORM client.
type AuditLogger struct {
	// factory produces the ORM client bound to the tenant being written to.
	factory *clientfactory.ClientFactory
}

// NewAuditLogger returns an audit logger backed by the given client factory.
func NewAuditLogger(factory *clientfactory.ClientFactory) *AuditLogger {
	return &AuditLogger{factory: factory}
}

// LogRBACEvent records one RBAC change.
//
// actorType is "admin", "system", or anything else for an end user; eventType is
// the dotted event name ("rbac.role.created"); targetType and targetID name what
// was changed and are folded into metadata alongside the caller's own fields. ip
// and userAgent are recorded when non-empty.
//
// It returns the write error. Callers treat audit logging as best-effort and
// discard it, so a failed record never turns a completed authority change into a
// reported failure.
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
