/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/audit/handler.go
 * Tier: HTTP REST Route Handler Layer
 *
 * Description: Fiber REST API route handler for admin audit logs query.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package audit

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/httperr"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/middleware"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
)

// Handler serves audit log queries for admin.
type Handler struct {
	factory *clientfactory.ClientFactory
}

// Page size bounds for the log listing. Audit logs are the highest-volume table
// in the engine — every authentication event appends one — so the maximum is what
// keeps a single request from selecting a tenant's entire history into memory and
// rendering it twice, once as rows and once as DTOs. A caller wanting the whole
// history pages through it.
const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// NewHandler returns an Audit handler bound to client factory.
func NewHandler(factory *clientfactory.ClientFactory) *Handler {
	return &Handler{factory: factory}
}

// RegisterRoutes mounts audit log routes.
func (h *Handler) RegisterRoutes(app *fiber.App, adminMiddleware fiber.Handler) {
	adminGroup := app.Group("/v1/admin/audit-logs")
	if adminMiddleware != nil {
		adminGroup.Use(adminMiddleware)
	}
	adminGroup.Get("", h.ListAuditLogs)
	adminGroup.Get("/", h.ListAuditLogs)
}

// AuditLogDTO represents an audit log entry returned to clients.
type AuditLogDTO struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	ActorType string                 `json:"actor_type"`
	ActorID   string                 `json:"actor_id,omitempty"`
	EventType string                 `json:"event_type"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt string                 `json:"created_at"`
}

// ListAuditLogs handles GET /v1/admin/audit-logs.
func (h *Handler) ListAuditLogs(c *fiber.Ctx) error {
	tenantID, okTenant := middleware.RequireTenantID(c)
	if !okTenant {
		return nil
	}

	client := h.factory.GetClient(c.UserContext(), tenantID, "")

	query := client.AuditLog.Query()

	if actorID := c.Query("actor_id"); actorID != "" {
		query.Where(auditlog.UserID(actorID))
	}
	if eventType := c.Query("event_type"); eventType != "" {
		query.Where(auditlog.EventType(eventType))
	}

	total, err := query.Count(c.UserContext())
	if err != nil {
		return httperr.SendInternal(c, "audit.count", err)
	}

	limit := defaultPageSize
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}

	offset := 0
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	logs, err := query.
		Order(ent.Desc(auditlog.FieldCreatedAt)).
		Limit(limit).
		Offset(offset).
		All(c.UserContext())
	if err != nil {
		return httperr.SendInternal(c, "audit.list", err)
	}

	dtos := make([]AuditLogDTO, 0, len(logs))
	for _, l := range logs {
		actorID := ""
		if l.UserID != nil {
			actorID = *l.UserID
		}
		dtos = append(dtos, AuditLogDTO{
			ID:        l.ID,
			TenantID:  l.TenantID,
			ActorType: string(l.ActorType),
			ActorID:   actorID,
			EventType: l.EventType,
			IPAddress: l.IPAddress,
			UserAgent: l.UserAgent,
			Metadata:  l.Metadata,
			CreatedAt: l.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	return c.JSON(fiber.Map{
		"logs":  dtos,
		"total": total,
		// The window is echoed because it is not always the one that was asked for:
		// a page size past the maximum comes back clamped, and a caller that could
		// not see that would read a short page as the end of the history.
		"limit":  limit,
		"offset": offset,
	})
}
