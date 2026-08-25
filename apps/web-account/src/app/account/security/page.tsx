import type { Metadata } from "next";
import type { ReactNode } from "react";
import { ShieldKeyIllustration } from "@authn/ui";
import { PageHeader } from "@/components/PageHeader";
import { SecurityCards } from "./SecurityCards";

/**
 * Authn Platform — Security page
 * File: apps/web-account/src/app/account/security/page.tsx
 *
 * Three cards, and their ids are the three children the sidebar shows under
 * Security. They are fragments of one page rather than three routes because the
 * question a reader arrives with is "how protected am I", and that question is
 * answered by seeing the factors together — split across three pages, each one
 * shows a single row and the answer has to be assembled from memory.
 *
 * The header is server-rendered and the cards are not: the heading and the drawing
 * are the same for everybody, while everything below them is this account's own
 * state and needs a session the server does not hold.
 */

export const metadata: Metadata = { title: "Security" };

export default function SecurityPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Security"
        description="Your password and the second factors that stand behind it. Two factors is the difference between a leaked password costing you an afternoon and costing you the account."
        illustration={ShieldKeyIllustration}
        accent="green"
      />

      <SecurityCards />
    </>
  );
}
