/**
 * Authn Platform — Help topics
 * File: apps/web-account/src/lib/docs.ts
 *
 * The explanations shown beside controls on the account pages, in one place.
 *
 * Two reasons they are not written inline. The first is that the same rule is
 * explained in more than one place — the username rules appear on the profile
 * page and again in the sign-up form — and two copies of a rule drift apart the
 * first time the rule changes. The second is the link: there is no published
 * documentation site yet, and collecting the paths here means adding one is
 * setting `NEXT_PUBLIC_AUTHN_DOCS_URL` rather than editing seven pages.
 *
 * Every summary is written to be complete on its own. A reader who never follows
 * the link still gets the answer, which is what stops the link from being the
 * place the real information went.
 */

import { env } from "./env";

export interface HelpTopic {
  /** Sentence-length answer. Complete without the link. */
  summary: string;
  /**
   * The fuller explanation, for somewhere with room: a card footer, an empty
   * state. Absent where the summary is already the whole answer.
   */
  detail?: string;
  /**
   * Path under the documentation site, matched to the file in `docs/` that
   * covers it. Kept here so the mapping is checkable against the repository.
   */
  path: string;
}

/**
 * Topics are keyed by what the reader is looking at, not by which endpoint
 * answers it, because that is what a call site knows.
 */
export const helpTopics = {
  username: {
    summary:
      "3 to 30 characters, letters, digits and underscores. Must start with a letter and cannot end with an underscore.",
    detail:
      "Capitals are kept for display but ignored when checking whether a handle is taken, so Ada and ada cannot both exist. Clearing your username releases it for anyone else to claim.",
    path: "/endpoints/client-user-profile",
  },
  password: {
    summary:
      "Changing your password signs out your other sessions. This one stays signed in.",
    detail:
      "You need your current password to set a new one, which is what stops someone who finds an unlocked screen from locking you out of your own account.",
    path: "/endpoints/client-user-profile",
  },
  emailChange: {
    summary:
      "We send a confirmation link to the new address. Your current address keeps working until you use it.",
    detail:
      "The link expires, and until it is used nothing about your account changes — so a change started by mistake needs no undoing.",
    path: "/endpoints/client-verify-email",
  },
  twoFactor: {
    summary:
      "A second step after your password, so a stolen password is not enough on its own.",
    detail:
      "An authenticator app is the most reliable option: it works with no signal and nothing to intercept. Text messages are easier to start with and easier to attack.",
    path: "/endpoints/mfa-enrollment-verification",
  },
  passkey: {
    summary:
      "Your device confirms it is you with a fingerprint, face or screen lock. Nothing is typed, so nothing can be phished.",
    detail:
      "The key never leaves the device, and each passkey is tied to this site alone — a copy of this page on another domain cannot ask for it.",
    path: "/endpoints/mfa-enrollment-verification",
  },
  recoveryCodes: {
    summary:
      "16 single-use codes that work in place of your second factor. Shown once, when generated.",
    detail:
      "We store only a hash, so we cannot show them again. Generating a new set immediately invalidates every code in the old one.",
    path: "/endpoints/client-account-recovery",
  },
  recoveryEmail: {
    summary:
      "A second address we can reach you at if you lose access to your main one.",
    detail:
      "Confirm it now, while you still can: a link goes to the address and only a confirmed one is any use later. No sign-in link is ever sent there and it cannot be used to sign in on its own.",
    path: "/endpoints/client-account-recovery",
  },
  guardians: {
    summary:
      "People you trust to confirm it is you. Recovery needs more than half of them to agree — two of three, three of five.",
    detail:
      "Invitations are not emailed for you: you get a link for each guardian and send it to them yourself, and a guardian who has not opened their link does not count yet. Removing a guardian re-issues everyone else's share, so the others do not need to do anything but the old shares stop working. One guardian on their own is a majority of one — add a second before you rely on this.",
    path: "/endpoints/client-account-recovery",
  },
  securityQuestions: {
    summary:
      "3 to 5 questions only you can answer, used as a last resort when nothing else is left.",
    detail:
      "Answers are stored the way a password is — hashed, never readable — and compared ignoring capitals and extra spaces, so the same answer typed months later on another keyboard still matches. Saving replaces the whole set at once, which is what stops someone with your unlocked screen from quietly adding a question they already know the answer to.",
    path: "/endpoints/client-account-recovery",
  },
  sessions: {
    summary:
      "Every browser and app currently signed in to this account. Revoking one signs it out at once.",
    detail:
      "Last used is when a device last renewed its sign-in rather than its last click, so an open tab can show a time from earlier today. Where a place is shown it is approximate — it comes from the IP address, so a VPN or a mobile network can put a session in the wrong city.",
    path: "/endpoints/client-sessions",
  },
  socialAccounts: {
    summary:
      "Services you can sign in with instead of your password. Each one is another way into this account.",
    detail:
      "Disconnecting removes that way in and nothing else — your account, and everything in it, stays exactly as it is.",
    path: "/endpoints/client-social-oauth",
  },
  organizations: {
    summary:
      "Shared workspaces you belong to. Your role in each one decides what you can do there.",
    detail:
      "Your account exists independently of any workspace, so losing access to one does not affect it. You can leave a workspace whatever your role, but removing somebody else needs organization-admin rights.",
    path: "/endpoints/client-organizations",
  },
  invitations: {
    summary:
      "An invitation arrives by email and stays valid for 7 days unless whoever sent it chose a different window.",
    detail:
      "Accepting one needs the code from that email. It is shown only to whoever sent the invitation, so a list of invitations addressed to you cannot accept them on your behalf.",
    path: "/endpoints/client-organizations",
  },
  deleteAccount: {
    summary: "Deleting your account is permanent. It cannot be undone by us or by you.",
    detail:
      "Your sessions end, your connected accounts are released, and your memberships in shared workspaces are removed.",
    path: "/endpoints/client-user-profile",
  },
} as const satisfies Record<string, HelpTopic>;

export type HelpTopicId = keyof typeof helpTopics;

/**
 * The documentation URL for a topic, or null while no documentation site is
 * configured.
 *
 * Null rather than "#" or the topic path on its own: a link that goes nowhere is
 * worse than no link, because the reader spends a click finding that out.
 */
export function helpHref(id: HelpTopicId): string | null {
  if (!env.docsUrl) return null;
  return `${env.docsUrl}${helpTopics[id].path}`;
}
