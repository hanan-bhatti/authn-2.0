/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/useradmin/repository.go
 * Tier: Data Access Layer / Admin User Directory
 *
 * Reads and writes over the user directory on behalf of a tenant administrator.
 *
 * Every method here runs under the request's privacy context, so the tenant and
 * environment boundary is applied beneath the query builder rather than by each
 * method. A row identifier arriving from a request therefore reaches only rows
 * the caller could have read, and a foreign identifier surfaces as ent's
 * not-found error.
 *
 * The listing is the one place that boundary is not the whole story: an
 * administrator paging a directory can ask for an unbounded page, and an
 * unbounded page over the largest table in the schema is a self-inflicted
 * outage. Page size is clamped here rather than trusted from the query string.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package useradmin

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/auditlog"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/predicate"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/clientfactory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/username"
)

// Page size bounds for the directory listing. The maximum exists to keep one
// request from selecting an entire tenant's users into memory; a caller wanting
// the whole directory pages through it.
const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// sortableFields is the allowlist of columns the listing may order by.
//
// The sort key arrives as a query parameter and ends up as an identifier in the
// generated ORDER BY, so it is mapped through this table rather than passed
// through. An unrecognised key falls back to the default rather than erroring:
// the handler rejects an unknown key before it reaches here, and this fallback
// is the safety net behind that check rather than the API's contract.
var sortableFields = map[string]string{
	"created_at":      user.FieldCreatedAt,
	"updated_at":      user.FieldUpdatedAt,
	"last_sign_in_at": user.FieldLastSignInAt,
	"email":           user.FieldEmail,
	"status":          user.FieldStatus,
}

// IsSortable reports whether key names a column the listing can order by, so the
// transport layer can reject an unknown key instead of quietly serving a
// differently ordered page.
func IsSortable(key string) bool {
	_, ok := sortableFields[key]
	return ok
}

// SortableFields returns the accepted sort keys in a stable order, for error
// messages and API documentation.
func SortableFields() []string {
	keys := make([]string, 0, len(sortableFields))
	for k := range sortableFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ListFilter narrows and pages the user directory.
//
// The zero value lists active-and-restricted users excluding soft-deleted rows,
// newest first, one default page. Nil pointer fields mean "no opinion" rather
// than a false or zero value, which is what separates ?email_verified=false from
// an absent parameter.
type ListFilter struct {
	// Status matches one user status exactly. Empty matches every status.
	Status string
	// Search matches a substring of email, name or username, case-insensitively.
	Search string
	// Email matches an email address exactly, for looking up a known account.
	Email string
	// EmailVerified filters on verification state when non-nil.
	EmailVerified *bool
	// IncludeDeleted keeps soft-deleted rows in the result. They are excluded by
	// default, so an administrator reading the directory sees the accounts that
	// still exist as far as sign-in is concerned.
	IncludeDeleted bool
	// OnlyDeleted restricts the result to soft-deleted rows, which is how a
	// console surfaces a restore queue. It takes precedence over IncludeDeleted.
	OnlyDeleted bool
	// CreatedAfter and CreatedBefore bound registration time when non-nil.
	CreatedAfter  *time.Time
	CreatedBefore *time.Time
	// Sort names a key in sortableFields. Ascending reverses the default
	// newest-first order; the polarity is that way round so the zero value already
	// means what a directory opens on, without the ordering having to tell an
	// unset preference apart from an explicit descending one.
	Sort      string
	Ascending bool
	// Limit and Offset page the result. Limit is clamped to maxPageSize and
	// defaults to defaultPageSize; a negative Offset is treated as zero.
	Limit  int
	Offset int
}

// Repository reads and writes users through a tenant-scoped ORM client.
type Repository struct {
	// factory produces the ORM client. The tenant and environment arguments are
	// passed for pool routing only — the boundary comes from the context.
	factory *clientfactory.ClientFactory
}

// NewRepository returns a repository backed by factory.
func NewRepository(factory *clientfactory.ClientFactory) *Repository {
	return &Repository{factory: factory}
}

// predicates translates f into Ent predicates.
//
// Deletion state is decided first and exclusively, so OnlyDeleted and
// IncludeDeleted cannot combine into a filter that means neither.
func (f ListFilter) predicates() []predicate.User {
	var preds []predicate.User

	switch {
	case f.OnlyDeleted:
		preds = append(preds, user.DeletedAtNotNil())
	case !f.IncludeDeleted:
		preds = append(preds, user.DeletedAtIsNil())
	}

	if f.Status != "" {
		preds = append(preds, user.StatusEQ(user.Status(f.Status)))
	}
	if f.Email != "" {
		preds = append(preds, user.EmailEQ(f.Email))
	}
	if f.Search != "" {
		preds = append(preds, user.Or(
			user.EmailContainsFold(f.Search),
			user.NameContainsFold(f.Search),
			user.UsernameContainsFold(f.Search),
		))
	}
	if f.EmailVerified != nil {
		preds = append(preds, user.EmailVerifiedEQ(*f.EmailVerified))
	}
	if f.CreatedAfter != nil {
		preds = append(preds, user.CreatedAtGTE(*f.CreatedAfter))
	}
	if f.CreatedBefore != nil {
		preds = append(preds, user.CreatedAtLTE(*f.CreatedBefore))
	}

	return preds
}

// page returns the clamped limit and offset f asks for.
func (f ListFilter) page() (limit, offset int) {
	limit = f.Limit
	switch {
	case limit <= 0:
		limit = defaultPageSize
	case limit > maxPageSize:
		limit = maxPageSize
	}

	offset = f.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// order returns the ordering option for f, defaulting to newest first.
//
// The direction is read from Ascending alone. Deriving it from the sort key as
// well would make the two parameters interact: an ascending page over the
// default column would come back descending, because the key that selects the
// column was never named.
func (f ListFilter) order() func(*ent.UserQuery) {
	field, ok := sortableFields[f.Sort]
	if !ok {
		field = user.FieldCreatedAt
	}

	return func(q *ent.UserQuery) {
		if f.Ascending {
			q.Order(ent.Asc(field))
			return
		}
		q.Order(ent.Desc(field))
	}
}

// List returns one page of the tenant's users and the total matching the filter
// before paging, so a caller can render a page count.
//
// The count and the page are two statements against a table that is being
// written to concurrently, so the total is a snapshot rather than a guarantee
// about the page that follows it.
func (r *Repository) List(ctx context.Context, f ListFilter) ([]*ent.User, int, error) {
	client := r.factory.GetClient(ctx, "", "")
	preds := f.predicates()

	total, err := client.User.Query().Where(preds...).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("counting users: %w", err)
	}

	limit, offset := f.page()
	query := client.User.Query().Where(preds...).Limit(limit).Offset(offset)
	f.order()(query)

	rows, err := query.All(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("listing users: %w", err)
	}
	return rows, total, nil
}

// Get returns one user by ID.
//
// A user in another tenant is reported as not found, because the privacy layer
// removes it from the result set before this ever sees it — which is also the
// answer an administrator of this tenant should get.
func (r *Repository) Get(ctx context.Context, userID string) (*ent.User, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.Get(ctx, userID)
}

// SetStatus writes a new account status.
func (r *Repository) SetStatus(ctx context.Context, userID string, status user.Status) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.UpdateOneID(userID).SetStatus(status).Exec(ctx)
}

// SoftDelete stamps deleted_at and releases the account's username handle,
// retiring the account without releasing its email address. The row is what
// reserves the address, so a hard delete would let the same address be registered
// again by someone else.
//
// The handle is treated the opposite way because an email address identifies a
// person outside the system while a handle only names them inside it: holding
// "alexsmith" out of circulation forever for an account nobody can sign into
// costs a live user a name for no protection. Clearing it here rather than
// filtering deleted rows out of the availability check is what keeps the check
// and the unique index looking at the same set of rows — a check that ignored
// deleted rows the index still indexes would report a handle free and then fail
// the write that claimed it.
func (r *Repository) SoftDelete(ctx context.Context, userID string, at time.Time) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.UpdateOneID(userID).
		SetDeletedAt(at).
		ClearUsername().
		ClearUsernameCanonical().
		Exec(ctx)
}

// Restore clears deleted_at, returning the account to whatever status it held.
//
// Status is deliberately untouched: deletion and status are separate fields, so
// restoring a user who was banned or frozen before deletion returns them to that
// restriction rather than to active.
func (r *Repository) Restore(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.UpdateOneID(userID).ClearDeletedAt().Exec(ctx)
}

// MarkEmailVerified marks the address verified and drops any outstanding
// verification token, so a link already in a mailbox cannot be replayed against
// an address an administrator has since confirmed by other means.
func (r *Repository) MarkEmailVerified(ctx context.Context, userID string) error {
	client := r.factory.GetClient(ctx, "", "")
	return client.User.UpdateOneID(userID).
		SetEmailVerified(true).
		ClearEmailVerificationToken().
		ClearEmailVerificationExpiresAt().
		Exec(ctx)
}

// LinkedProviders returns the social providers the user can sign in with, which
// is what tells a support operator whether an account locked out of its password
// still has a way in.
func (r *Repository) LinkedProviders(ctx context.Context, userID string) ([]string, error) {
	client := r.factory.GetClient(ctx, "", "")
	return client.Identity.Query().
		Where(identity.UserID(userID)).
		Order(ent.Asc(identity.FieldProvider)).
		Select(identity.FieldProvider).
		Strings(ctx)
}

// EnabledTwoFactorTypes returns the kinds of second factor the user currently
// has enabled, deduplicated, so that two passkeys report as one type.
//
// Disabled methods are omitted: a method row that is switched off cannot satisfy
// a challenge, and counting it would tell an operator an account is protected
// when it is not.
func (r *Repository) EnabledTwoFactorTypes(ctx context.Context, userID string) ([]string, error) {
	client := r.factory.GetClient(ctx, "", "")
	rows, err := client.TwoFactorMethod.Query().
		Where(
			twofactormethod.UserID(userID),
			twofactormethod.IsEnabled(true),
		).
		Order(ent.Asc(twofactormethod.FieldType)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(rows))
	types := make([]string, 0, len(rows))
	for _, row := range rows {
		t := string(row.Type)
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		types = append(types, t)
	}
	return types, nil
}

// ProfilePatch carries the profile fields an administrator may change on behalf
// of a user. A nil field is left alone, which is what lets one endpoint clear a
// value and omit another.
type ProfilePatch struct {
	Name        *string
	Username    *string
	AvatarURL   *string
	PhoneNumber *string
	Locale      *string
	// Metadata is merged key by key into the stored map rather than replacing it.
	// The column holds flags written by other flows — recovery-email verification
	// among them — so a replacing write would let a profile edit clear state it
	// never mentioned. A key set to nil is removed.
	Metadata map[string]interface{}
}

// IsEmpty reports whether the patch would change nothing.
func (p ProfilePatch) IsEmpty() bool {
	return p.Name == nil && p.Username == nil && p.AvatarURL == nil &&
		p.PhoneNumber == nil && p.Locale == nil && p.Metadata == nil
}

// mergeMetadata folds the patch's metadata into current, returning the map to
// store. A key whose value is nil is deleted, which is the only way an API using
// a merge can remove one.
func mergeMetadata(current, patch map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{}, len(current)+len(patch))
	for k, v := range current {
		merged[k] = v
	}
	for k, v := range patch {
		if v == nil {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	return merged
}

// TakenAmong returns the subset of candidates already held in the caller's scope,
// excluding the row identified by userID so that re-submitting one's own handle is
// not reported as a collision.
//
// Every candidate is answered by one query. Probing them one at a time would be
// the same index work spread over as many round trips as there are candidates,
// and the suggestion path asks about two dozen at once. The predicate is an
// equality set over the indexed canonical column, so the database touches exactly
// the keys named and the cost is set by len(candidates) rather than by the size of
// the table.
// // Soft-deleted rows are not filtered out, because SoftDelete clears the canonical
// column outright. The check and the unique index therefore examine the same set
// of rows, which is the property that matters: a check that skipped rows the index
// still indexes would report a handle free and then fail the write claiming it.
//
// The result is a set rather than a list so a caller filtering a candidate pool
// does so without a nested scan. Returns an empty map for empty input.
func (r *Repository) TakenAmong(ctx context.Context, userID string, candidates []string) (map[string]struct{}, error) {
	taken := make(map[string]struct{}, len(candidates))
	if len(candidates) == 0 {
		return taken, nil
	}

	predicates := []predicate.User{user.UsernameCanonicalIn(candidates...)}
	if userID != "" {
		predicates = append(predicates, user.IDNEQ(userID))
	}

	client := r.factory.GetClient(ctx, "", "")
	rows, err := client.User.Query().
		Where(predicates...).
		Select(user.FieldUsernameCanonical).
		All(ctx)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		if row.UsernameCanonical != nil {
			taken[*row.UsernameCanonical] = struct{}{}
		}
	}
	return taken, nil
}

// UsernameTaken reports whether another user in the caller's scope already holds
// canonical.
//
// This is the single-candidate form of TakenAmong and shares its scoping. It
// remains a check-then-write with a window between the two, so it is a way to
// return a useful error rather than the uniqueness guarantee: that is the unique
// index on (tenant_id, environment, username_canonical), which turns a lost race
// into a constraint violation instead of a duplicate row.
func (r *Repository) UsernameTaken(ctx context.Context, userID, canonical string) (bool, error) {
	if canonical == "" {
		return false, nil
	}
	taken, err := r.TakenAmong(ctx, userID, []string{canonical})
	if err != nil {
		return false, err
	}
	_, exists := taken[canonical]
	return exists, nil
}

// UpdateProfile applies p to the loaded user and returns the updated row.
//
// current supplies the metadata the merge builds on, so the caller's already
// loaded row is reused rather than read a second time.
//
// An empty username clears both username columns rather than storing a blank one,
// so the unique index holds no empty strings — one blank would otherwise reserve
// the empty handle for the whole scope. Changing a phone number clears its
// verified flag: the new number has not been proven, and carrying the old flag
// over would present an unverified number as verified.
//
// The display and canonical columns are written together here and nowhere else,
// which is what keeps them from disagreeing. A caller that set only the display
// form would leave a handle that no lookup finds and that the unique index does
// not protect.
func (r *Repository) UpdateProfile(ctx context.Context, current *ent.User, p ProfilePatch) (*ent.User, error) {
	client := r.factory.GetClient(ctx, "", "")
	builder := client.User.UpdateOneID(current.ID)

	if p.Name != nil {
		builder.SetName(*p.Name)
	}
	if p.Username != nil {
		if *p.Username == "" {
			builder.ClearUsername().ClearUsernameCanonical()
		} else {
			canonical, err := username.Canonical(*p.Username)
			if err != nil {
				return nil, err
			}
			builder.SetUsername(*p.Username).SetUsernameCanonical(canonical)
		}
	}
	if p.AvatarURL != nil {
		builder.SetAvatarURL(*p.AvatarURL)
	}
	if p.PhoneNumber != nil {
		builder.SetPhoneNumber(*p.PhoneNumber).SetPhoneVerified(false)
	}
	if p.Locale != nil {
		builder.SetLocale(*p.Locale)
	}
	if p.Metadata != nil {
		builder.SetMetadata(mergeMetadata(current.Metadata, p.Metadata))
	}

	return builder.Save(ctx)
}

// AuditEntry is one administrative action on a user account.
type AuditEntry struct {
	// TenantID owns the row. Required: the privacy layer refuses an unscoped write.
	TenantID string
	// TargetUserID is the account acted upon, recorded as the row's user_id so
	// that "everything that happened to this account" is a single indexed query.
	// The actor travels in APIKeyID and Metadata instead.
	TargetUserID string
	// EventType is the dotted event name, e.g. admin.user.banned.
	EventType string
	// APIKeyID names the secret key used, when the caller authenticated with one.
	APIKeyID string
	// IPAddress, UserAgent and Origin are the request's network context.
	IPAddress string
	UserAgent string
	Origin    string
	// Metadata carries the actor and the action's own detail.
	Metadata map[string]interface{}
}

// WriteAudit appends one administrative audit row.
//
// The error is returned rather than logged so the caller decides. Callers here
// treat it as best-effort: the account change is already durable by the time
// this runs, and reporting a completed ban as failed would invite an operator to
// retry an action that already took effect.
func (r *Repository) WriteAudit(ctx context.Context, e AuditEntry) error {
	client := r.factory.GetClient(ctx, e.TenantID, "")

	builder := client.AuditLog.Create().
		SetID(idgen.New("log")).
		SetTenantID(e.TenantID).
		SetActorType(auditlog.ActorTypeAdmin).
		SetEventType(e.EventType).
		SetMetadata(e.Metadata)

	if e.TargetUserID != "" {
		builder.SetUserID(e.TargetUserID)
	}
	if e.APIKeyID != "" {
		builder.SetAPIKeyID(e.APIKeyID)
	}
	if e.IPAddress != "" {
		builder.SetIPAddress(e.IPAddress)
	}
	if e.UserAgent != "" {
		builder.SetUserAgent(e.UserAgent)
	}
	if e.Origin != "" {
		builder.SetRequestOrigin(e.Origin)
	}

	_, err := builder.Save(ctx)
	return err
}
