/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/sessionactivity/sessionactivity.go
 * Tier: Session Layer / Per-Application Activity
 *
 * Records where a shared session has been used.
 *
 * A session is tenant-wide: one sign-in covers every application under the
 * tenant, and revoking it signs the user out of all of them. That is the
 * intended model, but it leaves the session's own last_active_at unable to say
 * more than "some application saw traffic". These functions maintain one row per
 * (session, application) pair so a session list can show which applications a
 * login has actually reached, without splitting the session or making
 * revocation partial.
 *
 * The application is read from the privacy context rather than passed in, which
 * is what lets the six session-creating paths in the auth service record
 * activity without any of them growing an application parameter. A context with
 * no application — a background job, an admin route that resolved no key —
 * records nothing rather than guessing.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package sessionactivity

import (
	"context"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/sessionappactivity"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
)

// Touch records that sessionID was just used at the application in ctx,
// creating the pairing on first use and stamping it afterwards.
//
// Returns nil when ctx names no application, so a caller on a path that has no
// application does not have to know whether it does.
//
// Write frequency is bounded by how often a client refreshes its access token,
// not by request volume: the callers are session creation and rotation, so a
// busy application costs one write per access-token lifetime per session rather
// than one per request.
func Touch(ctx context.Context, client *ent.Client, sessionID string) error {
	appID := applicationFromContext(ctx)
	if appID == "" || sessionID == "" {
		return nil
	}

	now := time.Now()

	// Update before insert, because the pairing already exists for every use
	// after the first — which is nearly all of them.
	touched, err := client.SessionAppActivity.Update().
		Where(
			sessionappactivity.SessionID(sessionID),
			sessionappactivity.ApplicationID(appID),
		).
		SetLastActiveAt(now).
		Save(ctx)
	if err != nil {
		return err
	}
	if touched > 0 {
		return nil
	}

	_, err = client.SessionAppActivity.Create().
		SetID(idgen.New("saa")).
		SetSessionID(sessionID).
		SetApplicationID(appID).
		SetFirstSeenAt(now).
		SetLastActiveAt(now).
		Save(ctx)
	// Two first requests from one session race here, and the unique index on the
	// pair lets exactly one of them insert. The loser has nothing left to do:
	// the row the winner wrote carries the timestamp it was about to write.
	if err != nil && !ent.IsConstraintError(err) {
		return err
	}
	return nil
}

// CarryForward moves the activity of oldSessionID onto newSessionID.
//
// Refreshing rotates a session: a successor row is created and the outgoing one
// is parked in its grace window. Activity has to follow the successor, or every
// refresh would start a fresh set of pairings and the table would grow with one
// row per application per rotation while the timestamps a session list reads
// stayed pinned to the moment of each rotation.
//
// Whether the successor already holds a pairing depends on the rotation path:
// one creates the successor and retires the old row in that order, so Touch has
// already recorded the refresh against the new session before this runs; the
// other has not. Rather than depend on which, a collision is treated as what it
// is — two rows for one pairing. The outgoing row survives, because it carries
// the first_seen_at that says when this login first reached the application, and
// it inherits the newer last_active_at from the row it absorbs.
func CarryForward(ctx context.Context, client *ent.Client, oldSessionID, newSessionID string) error {
	if oldSessionID == "" || newSessionID == "" || oldSessionID == newSessionID {
		return nil
	}

	outgoing, err := client.SessionAppActivity.Query().
		Where(sessionappactivity.SessionID(oldSessionID)).
		All(ctx)
	if err != nil {
		return err
	}

	for _, row := range outgoing {
		err := client.SessionAppActivity.UpdateOneID(row.ID).
			SetSessionID(newSessionID).
			Exec(ctx)
		if err == nil {
			continue
		}
		if !ent.IsConstraintError(err) {
			return err
		}

		duplicate, err := client.SessionAppActivity.Query().
			Where(
				sessionappactivity.SessionID(newSessionID),
				sessionappactivity.ApplicationID(row.ApplicationID),
			).
			Only(ctx)
		if err != nil {
			return err
		}
		if err := client.SessionAppActivity.DeleteOneID(duplicate.ID).Exec(ctx); err != nil {
			return err
		}

		move := client.SessionAppActivity.UpdateOneID(row.ID).SetSessionID(newSessionID)
		if duplicate.LastActiveAt.After(row.LastActiveAt) {
			move = move.SetLastActiveAt(duplicate.LastActiveAt)
		}
		if err := move.Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// applicationFromContext returns the application the request was authenticated
// for, or "" when the context carries none.
func applicationFromContext(ctx context.Context) string {
	p, ok := privacy.FromContext(ctx)
	if !ok || p == nil {
		return ""
	}
	return p.ApplicationID
}
