/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sandbox/sandbox.go
 * Tier: Internal Service Package / Sandbox Message Store
 *
 * Reads and writes the messages a test environment captures instead of sending,
 * and expires them on a schedule.
 *
 * Capturing is what makes a test environment that sends mail usable: a signup
 * runs end to end, the rendered message is inspected and the credential it
 * carries is used, without delivering to a real inbox or handset. What it
 * deliberately cannot establish is whether the configured provider works, since
 * nothing captured here ever reaches one. That question has its own endpoint.
 *
 * Security Notice:
 *   - Rows hold verification links and one-time codes in plain text, which is
 *     the point of the entity: a test harness has to read them. Every query runs
 *     through the privacy interceptor, so a read is confined to the caller's
 *     tenant and environment and a live credential cannot reach sandbox traffic.
 *   - Rows are swept by age rather than retained, so a long-lived test
 *     environment does not accumulate an open-ended archive of usable
 *     credentials.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sandboxmessage"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

// Page size bounds for an inbox listing.
const (
	// defaultListLimit is the page size when a caller names none.
	defaultListLimit = 50
	// maxListLimit caps a page. A stored body is a whole rendered document, so
	// an unbounded page is a single request that loads a tenant's entire capture
	// history into memory in order to serialize it.
	maxListLimit = 200
)

// ErrNoScope reports a capture attempted on a context carrying no tenant and
// environment.
//
// The store refuses rather than filling in a default. A row written under the
// wrong scope is invisible to the inbox that ought to show it, which reads as
// "the message was never sent" — the one conclusion a sandbox must never produce
// falsely.
var ErrNoScope = errors.New("sandbox: capture requires a tenant and environment in context")

// Message is one outbound message to record.
type Message struct {
	// Channel is the transport that would have carried it.
	Channel sandboxmessage.Channel
	// Recipient is the address it was sent to: an email address, or an E.164
	// number for SMS.
	Recipient string
	// Subject is the rendered subject line, empty for SMS.
	Subject string
	// Body is the rendered message, as the provider would have received it.
	Body string
	// Template identifies the message type, empty when it is not recognised.
	Template string
	// Code is the one-time code the message carries, empty when it carries none.
	Code string
	// Metadata holds the structured values lifted out of the body, such as the
	// action link and the plain-text alternative.
	Metadata map[string]interface{}
}

// Store reads and writes captured messages.
type Store struct {
	factory *clientfactory.ClientFactory
}

// NewStore returns a store bound to the client factory.
func NewStore(factory *clientfactory.ClientFactory) *Store {
	return &Store{factory: factory}
}

// Capture records a message that was not delivered.
//
// Tenant and environment come from the context's privacy scope rather than from
// the caller, so a row cannot claim an environment its sender was not acting in.
// The environment is set explicitly because the interceptor stamps only the
// tenant onto a new row, and letting the column's default apply would make every
// capture look like test traffic whether or not it was.
func (s *Store) Capture(ctx context.Context, m Message) (*ent.SandboxMessage, error) {
	p, ok := privacy.FromContext(ctx)
	if !ok || p.TenantID == "" || p.Environment == "" {
		return nil, ErrNoScope
	}

	create := s.factory.GetClient(ctx, p.TenantID, p.Environment).SandboxMessage.Create().
		SetID(idgen.New("sbxmsg")).
		SetTenantID(p.TenantID).
		SetEnvironment(sandboxmessage.Environment(p.Environment)).
		SetChannel(m.Channel).
		SetRecipient(m.Recipient).
		SetSubject(m.Subject).
		SetBody(m.Body).
		SetTemplate(m.Template).
		SetCode(m.Code)

	if len(m.Metadata) > 0 {
		create.SetMetadata(m.Metadata)
	}

	return create.Save(ctx)
}

// Filter narrows an inbox listing.
type Filter struct {
	// Channel keeps only email or only SMS when set.
	Channel string
	// Recipient keeps only messages addressed to one recipient when set.
	Recipient string
	// Limit is the page size, defaulted and capped by the store.
	Limit int
	// Offset is how many of the newest messages to skip.
	Offset int
}

// List returns one page of captured messages newest first, along with the total
// matching the filter before paging.
//
// The total is what tells a caller polling for a message whether more exist
// beyond the page it asked for, which a page-length check cannot answer.
func (s *Store) List(ctx context.Context, f Filter) ([]*ent.SandboxMessage, int, error) {
	p, ok := privacy.FromContext(ctx)
	if !ok || p.TenantID == "" {
		return nil, 0, ErrNoScope
	}

	query := s.factory.GetClient(ctx, p.TenantID, p.Environment).SandboxMessage.Query()
	if f.Channel != "" {
		query.Where(sandboxmessage.ChannelEQ(sandboxmessage.Channel(f.Channel)))
	}
	if f.Recipient != "" {
		query.Where(sandboxmessage.Recipient(f.Recipient))
	}

	total, err := query.Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("counting captured messages: %w", err)
	}

	limit := f.Limit
	switch {
	case limit <= 0:
		limit = defaultListLimit
	case limit > maxListLimit:
		limit = maxListLimit
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	messages, err := query.
		Order(ent.Desc(sandboxmessage.FieldCreatedAt)).
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("listing captured messages: %w", err)
	}

	return messages, total, nil
}

// Get returns one captured message by ID.
//
// A message belonging to another tenant is reported as not found rather than as
// forbidden, since distinguishing the two would confirm that the ID exists.
func (s *Store) Get(ctx context.Context, id string) (*ent.SandboxMessage, error) {
	p, ok := privacy.FromContext(ctx)
	if !ok || p.TenantID == "" {
		return nil, ErrNoScope
	}

	return s.factory.GetClient(ctx, p.TenantID, p.Environment).SandboxMessage.Query().
		Where(sandboxmessage.ID(id)).
		Only(ctx)
}

// Purge empties the caller's inbox and reports how many messages it removed.
//
// The tenant and environment predicates are stated here as well as applied by
// the interceptor. A delete carrying no predicate of its own is one line away
// from erasing every tenant's captures if it is ever run under a context that
// bypasses the boundary, and this operation is destructive enough not to rest on
// a single layer.
func (s *Store) Purge(ctx context.Context) (int, error) {
	p, ok := privacy.FromContext(ctx)
	if !ok || p.TenantID == "" || p.Environment == "" {
		return 0, ErrNoScope
	}

	return s.factory.GetClient(ctx, p.TenantID, p.Environment).SandboxMessage.Delete().
		Where(
			sandboxmessage.TenantID(p.TenantID),
			sandboxmessage.EnvironmentEQ(sandboxmessage.Environment(p.Environment)),
		).
		Exec(ctx)
}

// PurgeExpired deletes captures created before the cutoff across every tenant,
// in batches, and reports the total removed.
//
// It runs from the retention sweeper under a context that bypasses the tenant
// boundary, which is what lets one pass cover every tenant. Deleting in batches
// keeps a backlog from becoming one statement that holds locks across the whole
// table.
func (s *Store) PurgeExpired(ctx context.Context, before time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		return 0, fmt.Errorf("sandbox message purge: batch size must be positive, got %d", batchSize)
	}

	client := s.factory.GetClient(ctx, "", "")
	total := 0

	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		ids, err := client.SandboxMessage.Query().
			Where(sandboxmessage.CreatedAtLT(before)).
			Order(ent.Asc(sandboxmessage.FieldID)).
			Limit(batchSize).
			IDs(ctx)
		if err != nil {
			return total, fmt.Errorf("selecting expired captured messages: %w", err)
		}
		if len(ids) == 0 {
			return total, nil
		}

		removed, err := client.SandboxMessage.Delete().
			Where(sandboxmessage.IDIn(ids...)).
			Exec(ctx)
		if err != nil {
			return total, fmt.Errorf("deleting expired captured messages: %w", err)
		}
		total += removed

		if removed == 0 || len(ids) < batchSize {
			return total, nil
		}
	}
}
