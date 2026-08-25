import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { AuthShell } from "@/components/AuthShell";
import { SignInForm } from "./SignInForm";
import { env } from "@/lib/env";

/**
 * Authn Platform — Sign-in page
 * File: apps/web-account/src/app/sign-in/page.tsx
 *
 * The shell, its copy and its links render on the server; only the form is a
 * client component. The tenant's own branding — its product name and legal
 * links — lives in the bootstrap document the form fetches, which is a client
 * concern, so what is set here is the platform's default. A tenant-branded shell
 * is a later change that moves the fetch to the server.
 */

export const metadata: Metadata = {
  title: "Sign in",
  description: "Sign in to your Authn account to manage sessions, devices and security settings.",
};

export default function SignInPage(): ReactNode {
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
      <SignInForm />
    </AuthShell>
  );
}
