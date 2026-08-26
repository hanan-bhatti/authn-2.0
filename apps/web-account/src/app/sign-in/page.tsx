import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { CheckIcon } from "@authn/ui";
import { AuthShell } from "@/components/AuthShell";
import { SignInForm } from "./SignInForm";
import { env } from "@/lib/env";
import { firstParam, safeNextPath } from "@/lib/searchParams";

/**
 * Authn Platform — Sign-in page
 * File: apps/web-account/src/app/sign-in/page.tsx
 *
 * The shell, its copy and its links render on the server; only the form is a
 * client component. The tenant's own branding — its product name and legal
 * links — lives in the bootstrap document the form fetches, which is a client
 * concern, so what is set here is the platform's default. A tenant-branded shell
 * is a later change that moves the fetch to the server.
 *
 * `next` is read here rather than with `useSearchParams` in the form. Reading it
 * in a client component would make this page's static render illegal without a
 * Suspense boundary around the form, and the boundary would buy nothing: the
 * value is known before the form mounts.
 *
 * `deleted` arrives the same way, and for a reason particular to what it says: the
 * page that sends it here no longer has an account to speak for. Confirming a
 * deletion on the page being left would put the message on a route the guard is
 * about to replace, so the confirmation is handed to the destination instead.
 */

export const metadata: Metadata = {
  title: "Sign in",
  description: "Sign in to your Authn account to manage sessions, devices and security settings.",
};

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}): Promise<ReactNode> {
  const params = await searchParams;
  const destination = safeNextPath(firstParam(params["next"]));
  const wasDeleted = firstParam(params["deleted"]) === "1";

  return (
    <AuthShell
      brand={`Authn · v${env.appVersion}`}
      title="Sign in"
      subtitle="Use your email address or your username."
      footer={
        <>
          New here?{" "}
          <Link href="/sign-up" className="text-ink underline decoration-hairline-strong underline-offset-2 hover:decoration-ink">
            Create an account
          </Link>
        </>
      }
    >
      {wasDeleted ? (
        <div className="mb-lg flex items-start gap-sm rounded-md border border-accent-green/40 bg-accent-green/[0.06] p-md">
          <CheckIcon variant="line" size={16} className="mt-px shrink-0 text-accent-green" />
          <div className="flex flex-col gap-xxs">
            <p className="text-body-sm text-ink">Your account has been deleted.</p>
            <p className="text-caption text-charcoal">
              Every device it was signed in on has been signed out. Nothing is kept on our
              side, and the email address and username are free to use again — signing up
              with them starts a new, empty account rather than restoring this one.
            </p>
          </div>
        </div>
      ) : null}

      <SignInForm destination={destination} />
    </AuthShell>
  );
}
