import { Button } from "@authn/ui";
import { env } from "@/lib/env";

/**
 * Authn Platform — Account app index
 * File: apps/web-account/src/app/page.tsx
 *
 * Placeholder. Exercises one token from each family and one @authn/ui component
 * so that a scaffold problem — Tailwind not scanning the package, a webfont not
 * resolving — shows up here rather than inside a real page.
 */

export default function Home() {
  return (
    <main className="mx-auto flex min-h-dvh max-w-2xl flex-col justify-center gap-xl px-xl">
      <p className="font-mono text-caption tracking-wide text-mute uppercase">
        Authn · v{env.appVersion}
      </p>

      <h1 className="font-display text-display-lg text-ink">Your account</h1>

      <p className="text-body-md text-charcoal">
        Sign in, manage your sessions and devices, and secure your account.
      </p>

      <div className="flex gap-md">
        <Button variant="primary">Sign in</Button>
        <Button variant="secondary">Create account</Button>
      </div>
    </main>
  );
}
