import type { Metadata } from "next";
import type { ReactNode } from "react";
import {
  Badge,
  Button,
  ClockIcon,
  DevicesIllustration,
  GlobeIcon,
  MonitorIcon,
  PulseIcon,
  SmartphoneIcon,
  StatCard,
} from "@authn/ui";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { PageHeader } from "@/components/PageHeader";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";

/**
 * Authn Platform — Sessions page
 * File: apps/web-account/src/app/account/sessions/page.tsx
 *
 * A list rather than a table, and that is the responsiveness decision on this page.
 * Device, place, address and last-seen is four columns, and four columns at 375px
 * either overflow into a horizontal scroller — where the last column, the one
 * holding "sign out", is the one off-screen — or collapse to unreadable widths. As
 * rows whose secondary facts run together on one wrapping line, the same four facts
 * reflow with no scroller and no truncation.
 *
 * Structure and copy only: nothing here reads from `GET /v1/client/sessions`, and
 * no control is wired.
 */

export const metadata: Metadata = { title: "Sessions" };

export default function SessionsPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Sessions"
        description="Every device currently signed in as you. If one of these is not yours, sign it out and change your password — in that order."
        illustration={DevicesIllustration}
        accent="orange"
        actions={<Button variant="secondary">Sign out everywhere else</Button>}
      />

      <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
        {/* Three across from `sm`, stacked below it. Not `grid-cols-3` with a min
            width: at 375px a three-column grid of numbers gives each cell about
            100px, and "6 days ago" wraps to three lines inside it.

            Each figure is one the session list can answer on its own — a count, a
            newest timestamp, a set of distinct places. A stat that needs a second
            request is a stat that renders empty for as long as that takes. */}
        <div className="grid grid-cols-1 gap-md sm:grid-cols-3">
          <StatCard
            title="Active sessions"
            value={3}
            subtitle="2 on a computer, 1 on a phone"
            icon={<PulseIcon size={16} />}
          />
          <StatCard
            title="Newest sign-in"
            value="3h ago"
            subtitle="Chrome on macOS, London"
            icon={<ClockIcon size={16} />}
          />
          <StatCard
            title="Places seen"
            value={2}
            subtitle="London and Manchester"
            icon={<GlobeIcon size={16} />}
          />
        </div>

        <SettingsCard
          title="Signed in on"
          description="A session ends when you sign it out here, when it expires, or when you change your password."
          action={<InfoHint topic="sessions" label="sessions" position="left" />}
          footer={<HelpText topic="sessions" />}
        >
          {/* The current session is first and cannot be signed out from its own row —
              the control for that is "sign out" in the menu, which knows it is ending
              the session the reader is looking at the page from. A "revoke" button
              here would be a button that logs you out and then re-renders a page you
              are no longer allowed to see. */}
          <SettingsRow
            icon={MonitorIcon}
            accent="orange"
            label="Chrome 133 on macOS 15"
            value="London, United Kingdom"
            hint="92.40.•.• · Active now · Signed in 3 hours ago"
            action={<Badge variant="orange" dot>this device</Badge>}
          />
          <SettingsRow
            icon={SmartphoneIcon}
            accent="orange"
            label="Safari on iOS 18"
            value="London, United Kingdom"
            hint="92.40.•.• · Last active 2 hours ago · Signed in 2 days ago"
            action={<Button variant="secondary">Sign out</Button>}
          />
          <SettingsRow
            icon={MonitorIcon}
            label="Firefox 134 on Windows 11"
            value="Manchester, United Kingdom"
            hint="81.132.•.• · Last active 3 days ago · Signed in 9 days ago"
            action={<Button variant="secondary">Sign out</Button>}
          />
        </SettingsCard>
      </div>
    </>
  );
}
