"use client";

import { useCallback, useMemo, useState, type ReactNode } from "react";
import {
  Badge,
  Button,
  ClockIcon,
  GlobeIcon,
  MonitorIcon,
  PulseIcon,
  SmartphoneIcon,
  StatCard,
  TabletIcon,
  useToast,
  type IconComponent,
} from "@authn/ui";
import { useAuth } from "@authn/react";
import type { AuthnDeviceSession } from "@authn/js";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { LoadError, RowSkeleton } from "@/components/CardState";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";
import { formatDate, formatSince } from "@/lib/datetime";
import { useResource, type ResourceResult } from "@/lib/useResource";

/**
 * Authn Platform — Sessions page body
 * File: apps/web-account/src/app/account/sessions/SessionCards.tsx
 *
 * One read, `GET /v1/client/sessions`, and the two revocations that act on it.
 *
 * Everything on the page is derived from that one list, including the three figures
 * above it. A count, a newest timestamp and a set of distinct places are all
 * answerable from the rows already in hand, so none of them costs a second request
 * — and a stat that needs its own request is a stat that renders empty for as long
 * as that request takes, on the part of the page a reader looks at first.
 *
 * The page states only what the payload carries. `location` is empty on a
 * deployment with no geolocation, so a place is shown where there is one and the
 * address stands in where there is not; a row reading "Signed in from " is worse
 * than a row reading "172.19.0.1". The same rule sends the third figure between
 * counting places and counting addresses.
 */

/** One dialog at a time, carrying what it cannot act without. */
type Modal =
  | null
  | { kind: "revoke-one"; session: AuthnDeviceSession }
  /** The number of devices, counted from the list rather than taken from the reply. */
  | { kind: "revoke-others"; count: number };

export function SessionCards(): ReactNode {
  const { client, isAuthenticated } = useAuth();
  const toast = useToast();

  const loadSessions = useCallback(async (): Promise<ResourceResult<AuthnDeviceSession[]>> => {
    const result = await client.listSessions();
    return result.ok ? { ok: true, data: result.sessions } : { ok: false, error: result.error };
  }, [client]);

  const sessions = useResource(loadSessions, { enabled: isAuthenticated });

  const [modal, setModal] = useState<Modal>(null);
  const close = useCallback(() => setModal(null), []);

  /**
   * This device first, the engine's own order behind it.
   *
   * The engine sorts by last activity, which is the right order for the question
   * "which of these is not me" but puts the reader's own session wherever its last
   * refresh happens to fall. Pinning it to the top costs nothing — it is the one row
   * labelled as theirs — and it means the row that behaves differently, having no
   * sign-out button, is always in the same place.
   */
  const ordered = useMemo(() => {
    const list = sessions.data ?? [];
    return [...list].sort((a, b) => Number(b.isCurrent) - Number(a.isCurrent));
  }, [sessions.data]);

  const stats = useMemo(() => summarise(ordered), [ordered]);
  const otherCount = ordered.filter((session) => !session.isCurrent).length;

  const revokeOne = useCallback(
    async (session: AuthnDeviceSession) => {
      const result = await client.revokeSession(session.id);
      if (!result.ok) return result.error;

      close();
      void sessions.refetch();
      toast.success(
        "Signed out",
        `${session.device.label ?? "That device"} has been signed out. Whoever was using it will need your password to get back in.`,
      );
      return null;
    },
    [client, close, sessions, toast],
  );

  const revokeOthers = useCallback(
    async (count: number) => {
      const result = await client.revokeOtherSessions();
      if (!result.ok) return result.error;

      close();
      void sessions.refetch();
      // The server's count in preference to the one the button was labelled with.
      // It counts devices, not rows — the superseded predecessors a device leaves
      // behind on every refresh are ended too and deliberately not counted — and it
      // is the later of the two numbers, so it accounts for a session that expired
      // while the page sat open.
      const ended = result.count ?? count;
      toast.success(
        ended === 1 ? "1 other device signed out" : `${ended} other devices signed out`,
        "This device is still signed in. If you were signing out a device you no longer trust, change your password next.",
      );
      return null;
    },
    [client, close, sessions, toast],
  );

  return (
    <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
      {/* Three across from `sm`, stacked below it. Not `grid-cols-3` with a min
          width: at 375px a three-column grid of numbers gives each cell about
          100px, and "6 days ago" wraps to three lines inside it. */}
      {sessions.isLoading || stats ? (
        <div className="grid grid-cols-1 gap-md sm:grid-cols-3">
          <StatCard
            title="Active sessions"
            value={stats?.total ?? "…"}
            subtitle={stats?.formFactors}
            icon={<PulseIcon size={16} />}
          />
          <StatCard
            title="Newest sign-in"
            value={stats?.newestAge ?? "…"}
            subtitle={stats?.newestLabel}
            icon={<ClockIcon size={16} />}
          />
          <StatCard
            title={stats?.placeTitle ?? "Places seen"}
            value={stats?.placeCount ?? "…"}
            subtitle={stats?.placeList}
            icon={<GlobeIcon size={16} />}
          />
        </div>
      ) : null}

      <SettingsCard
        id="devices"
        title="Signed in on"
        description="A session ends when you sign it out here, when it expires, or when you change your password."
        action={
          <>
            <InfoHint topic="sessions" label="sessions" position="left" />
            {/* On the card rather than in the page header, which is where the
                mock-up had it. The button acts on this list and needs to know how
                many rows are in it — both to be disabled when there is nothing else
                to sign out, and to say how many devices it ended. In the header it
                would be a second component fetching the same list to find out. */}
            <Button
              variant="secondary"
              disabled={sessions.isLoading || otherCount === 0}
              onClick={() => setModal({ kind: "revoke-others", count: otherCount })}
            >
              Sign out everywhere else
            </Button>
          </>
        }
        footer={<HelpText topic="sessions" />}
      >
        {sessions.isLoading ? (
          <RowSkeleton rows={3} hasIcon label="your signed-in devices" />
        ) : !sessions.data ? (
          <LoadError
            label="your signed-in devices"
            message={sessions.error?.message}
            onRetry={() => void sessions.refetch()}
            isRetrying={sessions.isRefetching}
          />
        ) : (
          ordered.map((session) => (
            <SettingsRow
              key={session.id}
              icon={deviceIcon(session)}
              accent={session.isCurrent ? "orange" : undefined}
              label={session.device.label ?? "Unknown device"}
              value={describeWhere(session)}
              hint={describeWhen(session)}
              action={
                session.isCurrent ? (
                  /* The current session has no sign-out button. A button here would
                     sign the reader out and then re-render a page they are no longer
                     allowed to see; ending this one is what "Sign out" in the account
                     menu does, and that control knows to navigate afterwards. */
                  <Badge variant="orange" dot>
                    this device
                  </Badge>
                ) : (
                  <Button
                    variant="secondary"
                    onClick={() => setModal({ kind: "revoke-one", session })}
                  >
                    Sign out
                  </Button>
                )
              }
            />
          ))
        )}
      </SettingsCard>

      <ConfirmDialog
        isOpen={modal?.kind === "revoke-one"}
        onClose={close}
        title="Sign this device out?"
        description={
          modal?.kind === "revoke-one"
            ? `${modal.session.device.label ?? "That device"} loses access immediately. Signing in again needs your password, and your second factor if you have one.`
            : undefined
        }
        confirmLabel="Sign it out"
        cancelLabel="Leave it signed in"
        subject="sessions"
        onConfirm={() =>
          modal?.kind === "revoke-one" ? revokeOne(modal.session) : Promise.resolve(null)
        }
      >
        Your other devices, including this one, stay signed in.
      </ConfirmDialog>

      <ConfirmDialog
        isOpen={modal?.kind === "revoke-others"}
        onClose={close}
        title={
          modal?.kind === "revoke-others" && modal.count === 1
            ? "Sign out the one other device?"
            : "Sign out every other device?"
        }
        description="This device stays signed in. Every other one loses access immediately and has to sign in again."
        confirmLabel="Sign them out"
        cancelLabel="Leave them signed in"
        subject="sessions"
        consequence={
          /* Said before the click, not after. Someone signing out every device
             because they think the account is compromised has done half of the job,
             and the half they have done is the half that expires on its own. */
          "If you are doing this because you think someone else has your password, change your password afterwards. Signing devices out does not stop them signing back in."
        }
        onConfirm={() =>
          modal?.kind === "revoke-others" ? revokeOthers(modal.count) : Promise.resolve(null)
        }
      />
    </div>
  );
}

/** What the three figures above the list say, all derived from the list itself. */
interface SessionSummary {
  total: number;
  formFactors: string;
  newestAge: string;
  newestLabel: string;
  placeTitle: string;
  placeCount: number;
  placeList: string;
}

/**
 * Reduces the session list to the three figures, or null when there are none to
 * reduce.
 *
 * Null rather than a row of zeroes: an account always has at least the session
 * reading the page, so "0 active sessions" is not a state that exists — seeing it
 * would mean the read failed, and the card below already says so.
 */
function summarise(sessions: AuthnDeviceSession[]): SessionSummary | null {
  if (sessions.length === 0) return null;

  const factors = new Map<string, number>();
  for (const session of sessions) {
    const noun = formFactorNoun(session.device.device);
    factors.set(noun, (factors.get(noun) ?? 0) + 1);
  }
  const formFactors = asProse(
    [...factors.entries()].map(([noun, count]) =>
      count === 1 ? `1 ${noun}` : `${count} ${noun}s`,
    ),
  );

  const newest = sessions.reduce((latest, session) =>
    Date.parse(session.createdAt) > Date.parse(latest.createdAt) ? session : latest,
  );

  // Places where the deployment resolves them, addresses where it does not. The
  // heading changes with the figure, so neither reading is a guess about the other.
  const places = distinct(sessions.map((session) => session.location));
  const addresses = distinct(sessions.map((session) => session.ipAddress));
  const usePlaces = places.length > 0;
  const values = usePlaces ? places : addresses;

  return {
    total: sessions.length,
    formFactors,
    newestAge: formatSince(newest.createdAt),
    newestLabel: newest.isCurrent
      ? "This device"
      : (newest.device.label ?? "Unknown device"),
    placeTitle: usePlaces ? "Places seen" : "Addresses seen",
    placeCount: values.length,
    placeList: summariseList(values),
  };
}

/** The row's icon, one per form factor the engine reports. */
function deviceIcon(session: AuthnDeviceSession): IconComponent {
  switch (session.device.device) {
    case "Mobile":
      return SmartphoneIcon;
    case "Tablet":
      return TabletIcon;
    default:
      return MonitorIcon;
  }
}

/**
 * The row's prominent line: where the session is, as far as anything knows.
 *
 * A place when the deployment resolved one, the address when it did not, and a
 * plain statement when neither was recorded. The address is shown in full rather
 * than masked — it is the reader's own, and with no geolocation configured it is the
 * only thing that tells two of their devices apart.
 */
function describeWhere(session: AuthnDeviceSession): string {
  if (session.location) return session.location;
  if (session.ipAddress) return session.ipAddress;
  return "Address not recorded";
}

/**
 * The row's second line: form factor, then the two times that matter.
 *
 * "Last used" is the session's own timestamp, which advances when the device
 * renews its sign-in rather than on every request — so it is stated only when it
 * has moved away from the sign-in, and left out when the two are the same fact.
 * The expiry appears only inside the last week of the session's life, where it
 * stops being trivia and becomes the reason a device is about to ask for a
 * password.
 */
function describeWhen(session: AuthnDeviceSession): string {
  const parts = [formFactorLabel(session.device.device)];

  parts.push(`Signed in ${formatSince(session.createdAt)}`);

  if (session.isCurrent) {
    parts.push("Active now");
  } else if (session.lastActiveAt && movedOn(session.createdAt, session.lastActiveAt)) {
    parts.push(`Last used ${formatSince(session.lastActiveAt)}`);
  }

  if (session.expiresAt && expiringWithinAWeek(session.expiresAt)) {
    parts.push(`Expires ${formatDate(session.expiresAt)}`);
  }

  return parts.join(" · ");
}

/** Two minutes, which is longer than a sign-in takes and shorter than any refresh. */
const SAME_EVENT_MS = 2 * 60 * 1000;

/** Whether a last-used time is a separate event from the sign-in that created it. */
function movedOn(createdAt: string, lastActiveAt: string): boolean {
  const created = Date.parse(createdAt);
  const active = Date.parse(lastActiveAt);
  if (Number.isNaN(created) || Number.isNaN(active)) return false;
  return active - created > SAME_EVENT_MS;
}

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

function expiringWithinAWeek(expiresAt: string): boolean {
  const expires = Date.parse(expiresAt);
  if (Number.isNaN(expires)) return false;
  return expires - Date.now() < WEEK_MS;
}

/** The form factor as a heading-cased word, for the start of the hint. */
function formFactorLabel(device: string | undefined): string {
  switch (device) {
    case "Mobile":
      return "Phone";
    case "Tablet":
      return "Tablet";
    case "Desktop":
      return "Computer";
    default:
      return "Unrecognised device";
  }
}

/** The form factor as a countable noun, for "2 computers and 1 phone". */
function formFactorNoun(device: string | undefined): string {
  switch (device) {
    case "Mobile":
      return "phone";
    case "Tablet":
      return "tablet";
    case "Desktop":
      return "computer";
    default:
      return "other device";
  }
}

/** Distinct non-empty values, in the order they first appear. */
function distinct(values: (string | undefined)[]): string[] {
  const seen: string[] = [];
  for (const value of values) {
    if (value && !seen.includes(value)) seen.push(value);
  }
  return seen;
}

/**
 * A short list as a subtitle: two named, the rest counted.
 *
 * A stat card's subtitle is one line. Five addresses listed in it wrap to three
 * lines and push the card taller than its neighbours, so the tail is summarised
 * rather than truncated — "+3 more" is a fact, an ellipsis is not.
 */
function summariseList(values: string[]): string {
  if (values.length === 0) return "";
  if (values.length <= 2) return asProse(values);
  return `${values.slice(0, 2).join(", ")} and ${values.length - 2} more`;
}

/** Joins a short list the way a sentence would: "a, b and c". */
function asProse(items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}
