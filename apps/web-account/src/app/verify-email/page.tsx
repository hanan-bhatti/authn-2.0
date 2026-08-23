import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { AuthShell } from "@/components/AuthShell";
import { VerifyEmailPanel } from "./VerifyEmailPanel";
import { env } from "@/lib/env";
import { firstParam } from "@/lib/searchParams";

/**
 * Authn Platform — Email verification landing
 * File: apps/web-account/src/app/verify-email/page.tsx
 *
 * Where the link in a verification email lands. It used to point straight at the
 * engine, which cannot work: a click from a mail client carries no
 * publishable-key header, so the request was refused, and the user saw a JSON
 * error instead of a confirmation.
 *
 * The token is read here and handed down rather than read from the browser,
 * because the panel below removes it from the address bar as soon as it has been
 * used. Reading it client-side would race that.
 */

export const metadata: Metadata = {
  title: "Verify your email",
  description: "Confirm your email address to finish setting up your Authn account.",
};

export default async function VerifyEmailPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}): Promise<ReactNode> {
  const params = await searchParams;

  return (
    <AuthShell
      brand={`Authn · v${env.appVersion}`}
      title="Verify your email"
      footer={
        <>
          Nothing to verify?{" "}
          <Link
            href="/sign-in"
            className="text-ink underline decoration-hairline-strong underline-offset-2 hover:decoration-ink"
          >
            Sign in
          </Link>
        </>
      }
    >
      <VerifyEmailPanel token={firstParam(params["token"])} />
    </AuthShell>
  );
}
