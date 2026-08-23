import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { AuthShell } from "@/components/AuthShell";
import { MagicLinkPanel } from "./MagicLinkPanel";
import { env } from "@/lib/env";
import { firstParam } from "@/lib/searchParams";

/**
 * Authn Platform — Magic-link landing
 * File: apps/web-account/src/app/magic-link/page.tsx
 *
 * Where the link in a passwordless sign-in email lands. This is the one that had
 * to move most urgently: the link used to point at the engine's verify route,
 * which answers a top-level browser navigation with an access token in its
 * response body — a credential rendered into a window and its history, sent as
 * the Referer of anything that page went on to load.
 *
 * The token is posted from here instead, and the session comes back as cookies.
 */

export const metadata: Metadata = {
  title: "Signing you in",
  description: "Finish signing in to your Authn account.",
};

export default async function MagicLinkPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}): Promise<ReactNode> {
  const params = await searchParams;

  return (
    <AuthShell
      brand={`Authn · v${env.appVersion}`}
      title="Signing you in"
      footer={
        <>
          Need a new link?{" "}
          <Link
            href="/sign-in"
            className="text-ink underline decoration-hairline-strong underline-offset-2 hover:decoration-ink"
          >
            Sign in
          </Link>
        </>
      }
    >
      <MagicLinkPanel token={firstParam(params["token"])} />
    </AuthShell>
  );
}
