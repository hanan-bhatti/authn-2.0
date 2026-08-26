import type { Metadata } from "next";
import type { ReactNode } from "react";
import { DevicesIllustration } from "@authn/ui";
import { PageHeader } from "@/components/PageHeader";
import { SessionCards } from "./SessionCards";

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
 * The header is server-rendered and the list is not: the heading and the drawing
 * are the same for everybody, while the devices below them are this account's own
 * and need a session the server does not hold.
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
      />

      <SessionCards />
    </>
  );
}
