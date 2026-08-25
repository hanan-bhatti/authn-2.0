import type { Metadata } from "next";
import type { ReactNode } from "react";
import { env } from "@/lib/env";
import { HomeActions } from "./HomeActions";

/**
 * Authn Platform — Account app index
 * File: apps/web-account/src/app/page.tsx
 *
 * The way in. Everything a visitor can reach without being signed in leads from
 * here, and a visitor who already has a session is offered their account rather
 * than being asked to sign in again.
 */

export const metadata: Metadata = {
  title: "Your account",
  description:
    "Sign in to manage your profile, sessions, devices, two-step verification and recovery options.",
};

export default function Home(): ReactNode {
  return (
    <main className="mx-auto flex min-h-dvh max-w-2xl flex-col justify-center gap-xl px-xl">
      <p className="font-mono text-caption tracking-wide text-mute uppercase">
        Authn · v{env.appVersion}
      </p>

      <h1 className="font-display text-display-lg text-ink">Your account</h1>

      <p className="text-body-md text-charcoal">
        One place for your profile, the devices you are signed in on, two-step
        verification and how you get back in if you lose access.
      </p>

      <HomeActions />
    </main>
  );
}
