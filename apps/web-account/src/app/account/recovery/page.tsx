import type { Metadata } from "next";
import type { ReactNode } from "react";
import { BuoyIllustration } from "@authn/ui";
import { PageHeader } from "@/components/PageHeader";
import { RecoveryCards } from "./RecoveryCards";

/**
 * Authn Platform — Recovery page
 * File: apps/web-account/src/app/account/recovery/page.tsx
 *
 * The one page written for a reader who is not in trouble yet, about what happens
 * when they are. That shapes the copy: every row says what it will and will not
 * recover, because a recovery method someone believes in and cannot use is worse
 * than one they know is missing.
 *
 * Yellow, not green. Green on this page would say "you are protected", and the
 * honest claim is "you have a way back if something goes wrong" — which is a state
 * worth checking, not a state to be satisfied with.
 *
 * The header is server-rendered and the cards are not: the heading and the drawing
 * are the same for everybody, while what is actually set up belongs to this account
 * and needs a session the server does not hold.
 */

export const metadata: Metadata = { title: "Recovery" };

export default function RecoveryPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Recovery"
        description="How you get back in when the password is gone, the phone is lost, or both. Set at least two of these up now — none of them can be added once you are locked out."
        illustration={BuoyIllustration}
        accent="yellow"
      />

      <RecoveryCards />
    </>
  );
}
