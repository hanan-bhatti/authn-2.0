//go:build integration

/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/test/audit_logs_test.go
 * Tier: Integration Tests / Administrative Audit Trail
 *
 * Drives /v1/admin/audit-logs through the real admin guard. The audit table is
 * the largest one in the engine — every authentication event appends a row — so
 * the paging assertions here are about how much of it one request can pull, not
 * only about the shape of the reply.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package integration_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
)

// auditLogDTO mirrors the fields of a log entry these tests assert on. Partial on
// purpose: the projection carries more, and listing all of it would turn an added
// field into a failure.
type auditLogDTO struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	ActorType string `json:"actor_type"`
	EventType string `json:"event_type"`
	CreatedAt string `json:"created_at"`
}

// auditLogListReply is one page of the audit trail.
type auditLogListReply struct {
	Logs   []auditLogDTO `json:"logs"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

// seedAuditLogs appends count entries under one event type, which is what lets a
// test assert on an exact total: the filter isolates its own fixtures from
// whatever else the deployment has recorded.
func (e *testEnv) seedAuditLogs(t *testing.T, eventType string, count int) {
	t.Helper()

	ctx := e.bypassContext()
	client := e.client(ctx)

	builders := make([]*ent.AuditLogCreate, 0, count)
	for i := 0; i < count; i++ {
		builders = append(builders, client.AuditLog.Create().
			SetID(fmt.Sprintf("log_%s_%04d", eventType, i)).
			SetTenantID(testTenant).
			SetEventType(eventType))
	}

	if _, err := client.AuditLog.CreateBulk(builders...).Save(ctx); err != nil {
		t.Fatalf("seeding %d audit logs: %v", count, err)
	}
}

// TestAuditLogListCapsThePageSize is the memory bound. An unbounded page size
// would let one query select an entire tenant's history and render it twice, once
// as rows and once as DTOs, on nothing more than a query parameter.
func TestAuditLogListCapsThePageSize(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	const eventType = "test.paging"
	const seeded = 201
	env.seedAuditLogs(t, eventType, seeded)

	t.Run("a page size past the maximum is capped", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/audit-logs?event_type="+eventType+"&limit=10000", nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page auditLogListReply
		resp.json(t, &page)

		if len(page.Logs) >= seeded {
			t.Fatalf("page holds %d entries of %d seeded; the page size was not capped", len(page.Logs), seeded)
		}
		// The cap has to bound the query, not just the number the reply reports.
		if len(page.Logs) != page.Limit {
			t.Errorf("page holds %d entries but reports a limit of %d", len(page.Logs), page.Limit)
		}
		// The total describes the filter rather than the page, so a console can
		// tell a capped page from the end of the history.
		if page.Total != seeded {
			t.Errorf("total = %d, want %d", page.Total, seeded)
		}
	})

	t.Run("a page size within the maximum is honoured", func(t *testing.T) {
		resp := env.admin(t, http.MethodGet, "/v1/admin/audit-logs?event_type="+eventType+"&limit=5&offset=2", nil)
		assertStatus(t, "list", resp, http.StatusOK)

		var page auditLogListReply
		resp.json(t, &page)

		if len(page.Logs) != 5 {
			t.Errorf("page holds %d entries, want 5", len(page.Logs))
		}
		if page.Limit != 5 || page.Offset != 2 {
			t.Errorf("echoed window = limit %d offset %d, want 5/2", page.Limit, page.Offset)
		}
	})
}

// TestAuditLogListFiltersByEventType covers the filter an operator reaches for
// when investigating one kind of event.
func TestAuditLogListFiltersByEventType(t *testing.T) {
	env := newTestEnv(t, nil, nil)

	env.seedAuditLogs(t, "test.signin", 3)
	env.seedAuditLogs(t, "test.revocation", 2)

	resp := env.admin(t, http.MethodGet, "/v1/admin/audit-logs?event_type=test.revocation", nil)
	assertStatus(t, "list", resp, http.StatusOK)

	var page auditLogListReply
	resp.json(t, &page)

	if page.Total != 2 {
		t.Fatalf("total = %d, want the 2 matching entries", page.Total)
	}
	for _, entry := range page.Logs {
		if entry.EventType != "test.revocation" {
			t.Errorf("filtered page carries a %s entry", entry.EventType)
		}
		if entry.TenantID != testTenant {
			t.Errorf("entry belongs to tenant %s, want %s", entry.TenantID, testTenant)
		}
	}
}

// TestAuditLogListRequiresAnAdminCredential guards the trail itself: the entries
// name who signed in, from which address, at what time.
func TestAuditLogListRequiresAnAdminCredential(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	env.seedAuditLogs(t, "test.protected", 1)

	t.Run("no credential", func(t *testing.T) {
		resp := env.do(t, http.MethodGet, "/v1/admin/audit-logs", nil)
		assertRefusedWith(t, "list", resp, http.StatusUnauthorized, codeUnauthorized)
	})

	t.Run("a publishable key", func(t *testing.T) {
		resp := env.do(t, http.MethodGet, "/v1/admin/audit-logs", nil,
			withHeader("X-Authn-Publishable-Key", publishableKey))
		assertRefusedWith(t, "list", resp, http.StatusUnauthorized, codeUnauthorized)
	})
}
