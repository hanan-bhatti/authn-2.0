import type { AuthnError } from "./errors";

/**
 * One guardian's invitation link, paired with the person it belongs to.
 *
 * Deliver these yourself — the engine does not email them. The account holder is the only
 * party who knows which address really reaches which guardian, and a link sent to the wrong
 * person hands them someone else's share.
 *
 * Shown once. The `url` fragment carries a secret the engine keeps only a digest of, so a
 * client that discards this object has destroyed that guardian's half of the recovery proof
 * and the only remedy is {@link AuthnClient.revokeGuardian} followed by a fresh invitation.
 */
export interface GuardianInviteLink {
  contactId: string;
  guardianEmail: string;
  guardianName: string;
  url: string;
}

export interface AuthnGuardian {
  id: string;
  guardianEmail: string;
  guardianName: string;
  /**
   * The guardian's enrollment slot, 1 to 5. Unique per account and stable: revoking a
   * guardian frees their slot rather than renumbering the others, so this is not a position
   * in the roster and gaps are normal.
   */
  shareIndex: number;
  status: string;
  createdAt: string;
}

export interface InviteGuardianInput {
  email: string;
  name: string;
}

export interface InviteGuardiansParams {
  guardians: InviteGuardianInput[];
}

export type InviteGuardiansResult =
  | {
      ok: true;
      /** Guardians on the roster after this call, including any enrolled earlier. */
      enrolledCount: number;
      /**
       * How many guardians will have to approve a recovery once every one of them has
       * accepted: a majority of `enrolledCount`, `floor(n / 2) + 1`.
       *
       * Not the threshold in force right now. Only an accepted guardian can submit
       * anything, so the engine derives the live threshold from the accepted ones alone —
       * a roster of four with one invitation still outstanding needs two approvals today
       * and three once that person opens their link. Read {@link AuthnClient.listGuardians},
       * count the guardians whose `status` is `active`, and take a majority of those for
       * the number to show a user.
       */
      thresholdK: number;
      /** The guardians created by this call. Existing ones are untouched and not returned. */
      guardians: AuthnGuardian[];
      /** One link per guardian created by this call, in the same order. */
      invites: GuardianInviteLink[];
    }
  | { ok: false; error: AuthnError };

/**
 * AcceptGuardianInviteParams carries both halves of the invitation link.
 *
 * `token` and `share` live in the link's fragment (`#token=…&share=…`), which a browser never
 * sends to a server — read them client-side from `window.location.hash`, not from the query
 * string. The token proves the link is genuine; the share is the secret this guardian will
 * later submit to approve a recovery, and it is checked here so a link truncated in transit
 * fails now rather than during a lockout.
 */
export interface AcceptGuardianInviteParams {
  contactId: string;
  token: string;
  share: string;
}

export type AcceptGuardianInviteResult =
  | { ok: true; message: string }
  | { ok: false; error: AuthnError };

export type ListGuardiansResult =
  | { ok: true; guardians: AuthnGuardian[] }
  | { ok: false; error: AuthnError };

export type RevokeGuardianResult =
  | { ok: true; message: string }
  | { ok: false; error: AuthnError };
