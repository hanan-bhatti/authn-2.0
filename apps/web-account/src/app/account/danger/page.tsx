import type { Metadata } from "next";
import type { ReactNode } from "react";
import { ShredderIllustration } from "@authn/ui";
import { PageHeader } from "@/components/PageHeader";
import { DangerCards } from "./DangerCards";

/**
 * Authn Platform — Danger zone
 * File: apps/web-account/src/app/account/danger/page.tsx
 *
 * The whole page exists to slow one request down. `DELETE /v1/client/user/account`
 * is the only thing the engine offers here — there is no export and no
 * deactivation, so nothing on this page suggests either. What stands in front of
 * the button instead is the pair of consequences the reader cannot see from where
 * they are standing: their memberships go with them, and nothing is recoverable
 * afterwards.
 *
 * The one page in the account with a full-strength accent on its illustration, and
 * the one card with the accent on its border rather than a hairline. A reader
 * skimming identically framed cards has been given no signal which one is
 * different in kind.
 */

export const metadata: Metadata = { title: "Delete account" };

export default function DangerPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Delete account"
        description="One request, and it cannot be taken back. Two things are worth settling before you make it."
        illustration={ShredderIllustration}
        accent="red"
      />

      <DangerCards />
    </>
  );
}
