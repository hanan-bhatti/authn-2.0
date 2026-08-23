import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { AuthShell } from "@/components/AuthShell";
import { SignUpForm } from "./SignUpForm";
import { env } from "@/lib/env";

/**
 * Authn Platform — Sign-up page
 * File: apps/web-account/src/app/sign-up/page.tsx
 *
 * The shell, its copy and its links render on the server; only the form is a
 * client component. The tenant's own branding — its product name and legal
 * links — lives in the bootstrap document the form fetches, which is a client
 * concern, so what is set here is the platform's default. A tenant-branded shell
 * is a later change that moves the fetch to the server.
 */

export const metadata: Metadata = {
  title: "Create your account",
  description: "Create an Authn account to manage your sessions, devices and security settings.",
};

export default function SignUpPage(): ReactNode {
  return (
    <AuthShell
      brand={`Authn · v${env.appVersion}`}
      title="Create your account"
      subtitle="One account for your sessions, devices and security settings."
      footer={
        <>
          Already have an account?{" "}
          <Link href="/sign-in" className="text-ink underline decoration-hairline-strong underline-offset-2 hover:decoration-ink">
            Sign in
          </Link>
        </>
      }
    >
      <SignUpForm />
    </AuthShell>
  );
}
