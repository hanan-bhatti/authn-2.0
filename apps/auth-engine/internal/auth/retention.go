/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/retention.go
 * Tier: Internal Feature Package / Auth Retention
 *
 * Description: The users table's retention rule. Test-environment accounts left
 *              untouched for long enough are deleted along with everything that
 *              hangs off them; live accounts are never swept, because an idle
 *              customer is still a customer. Scheduling belongs to the retention
 *              sweeper, which decides when this runs and how long it may take.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/identity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/orgmember"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/pushdevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoverycontact"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/recoveryrequest"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/session"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/trusteddevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/twofactormethod"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/user"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/useripsubnethistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userpasswordhistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/userrole"
)

// PurgeIdleTestUsers deletes test-environment accounts idle since before
// idleBefore, and returns how many accounts it removed. It requires a context
// carrying a privacy bypass, because the sweep spans every tenant.
//
// Idle means the account has not signed in since the cutoff, or — for one that
// never signed in at all — was registered before it. Registration is the fallback
// rather than last_sign_in_at being treated as absent, because an abandoned
// half-finished signup is the most common thing a suite leaves behind and would
// otherwise be the one row class that accumulates forever.
//
// Every environment other than test is left alone by predicate rather than by the
// caller's choice of cutoff, so a misconfigured retention window cannot reach a
// live account.
//
// Deletion is batched for the reasons PurgeExpiredSessions gives, and each batch
// runs in its own transaction. The transaction is what keeps a partly deleted
// account from existing: an account whose second factors were removed but whose
// password hash survived would be a weakened account rather than an absent one.
func (r *Repository) PurgeIdleTestUsers(ctx context.Context, idleBefore time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		return 0, fmt.Errorf("idle test user purge: batch size must be positive, got %d", batchSize)
	}

	client := r.factory.GetClient(ctx, "", "")
	idle := user.And(
		user.EnvironmentEQ(user.EnvironmentTest),
		user.Or(
			user.LastSignInAtLT(idleBefore),
			user.And(user.LastSignInAtIsNil(), user.CreatedAtLT(idleBefore)),
		),
	)
	total := 0

	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		ids, err := client.User.Query().
			Where(idle).
			Order(ent.Asc(user.FieldID)).
			Limit(batchSize).
			IDs(ctx)
		if err != nil {
			return total, fmt.Errorf("selecting idle test users to purge: %w", err)
		}
		if len(ids) == 0 {
			return total, nil
		}

		removed, err := purgeUserBatch(ctx, client, ids)
		total += removed
		if err != nil {
			return total, err
		}

		// A batch that selected rows but removed none means something outside this
		// predicate is holding them, and re-selecting the same rows would spin. The
		// next sweep can revisit them.
		if removed == 0 || len(ids) < batchSize {
			return total, nil
		}
	}
}

// purgeUserBatch removes one batch of accounts and everything referencing them,
// reporting how many accounts went.
//
// The dependent tables are cleared first because their foreign keys are declared
// with no delete action: the database refuses to remove an account while any of
// them still points at it. Session activity is the exception and is left to the
// database, its key being the one declared to cascade.
func purgeUserBatch(ctx context.Context, client *ent.Client, ids []string) (int, error) {
	tx, err := client.Tx(ctx)
	if err != nil {
		return 0, fmt.Errorf("opening transaction to purge idle test users: %w", err)
	}
	defer tx.Rollback()

	dependents := []struct {
		name string
		del  func() (int, error)
	}{
		{"sessions", func() (int, error) { return tx.Session.Delete().Where(session.UserIDIn(ids...)).Exec(ctx) }},
		{"identities", func() (int, error) { return tx.Identity.Delete().Where(identity.UserIDIn(ids...)).Exec(ctx) }},
		{"two-factor methods", func() (int, error) {
			return tx.TwoFactorMethod.Delete().Where(twofactormethod.UserIDIn(ids...)).Exec(ctx)
		}},
		{"push devices", func() (int, error) {
			return tx.PushDevice.Delete().Where(pushdevice.UserIDIn(ids...)).Exec(ctx)
		}},
		{"trusted devices", func() (int, error) {
			return tx.TrustedDevice.Delete().Where(trusteddevice.UserIDIn(ids...)).Exec(ctx)
		}},
		{"subnet history", func() (int, error) {
			return tx.UserIpSubnetHistory.Delete().Where(useripsubnethistory.UserIDIn(ids...)).Exec(ctx)
		}},
		{"organization memberships", func() (int, error) {
			return tx.OrgMember.Delete().Where(orgmember.UserIDIn(ids...)).Exec(ctx)
		}},
		{"role assignments", func() (int, error) {
			return tx.UserRole.Delete().Where(userrole.UserIDIn(ids...)).Exec(ctx)
		}},
		{"recovery contacts", func() (int, error) {
			return tx.RecoveryContact.Delete().Where(recoverycontact.UserIDIn(ids...)).Exec(ctx)
		}},
		{"recovery requests", func() (int, error) {
			return tx.RecoveryRequest.Delete().Where(recoveryrequest.UserIDIn(ids...)).Exec(ctx)
		}},
		{"password history", func() (int, error) {
			return tx.UserPasswordHistory.Delete().Where(userpasswordhistory.UserIDIn(ids...)).Exec(ctx)
		}},
	}

	for _, dependent := range dependents {
		if _, err := dependent.del(); err != nil {
			return 0, fmt.Errorf("deleting %s of idle test users: %w", dependent.name, err)
		}
	}

	removed, err := tx.User.Delete().Where(user.IDIn(ids...)).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("deleting idle test users: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing idle test user purge: %w", err)
	}

	return removed, nil
}
