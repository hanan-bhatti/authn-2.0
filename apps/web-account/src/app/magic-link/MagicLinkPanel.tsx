"use client";

/**
 * Authn Platform — Magic-link panel
 * File: apps/web-account/src/app/magic-link/MagicLinkPanel.tsx
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@authn/ui";
import { useMagicLink } from "@authn/react";
import type { AuthnUser } from "@authn/js";
import { LinkStatusPanel } from "@/components/LinkStatusPanel";
import { presentLinkError } from "@/lib/linkError";
import { useEmailedToken } from "@/lib/useEmailedToken";

export function MagicLinkPanel({ token }: { token: string | undefined }): ReactNode {
  const { verifyMagicLink } = useMagicLink();
  const router = useRouter();

  // An accepted token does not always mean a session. When the account holds a
  // second factor the engine answers with a challenge, and this holds who is
  // signing in so the panel can say so.
  const [challenged, setChallenged] = useState<AuthnUser | null>(null);

  const redeem = useCallback(
    async (value: string) => {
      const result = await verifyMagicLink({ token: value });
      if (result.ok && result.mfaRequired) {
        // Recorded here rather than widened into the hook's contract: the hook's
        // question is whether the token was accepted, and what an accepted token
        // yielded is this page's business. redeem runs once, so this cannot be
        // set twice.
        setChallenged(result.user);
      }
      return result;
    },
    [verifyMagicLink],
  );

  const { state, retry } = useEmailedToken(token, redeem);

  const isSignedIn = state.status === "done" && !challenged;

  const navigated = useRef(false);
  useEffect(() => {
    if (!isSignedIn || navigated.current) return;
    navigated.current = true;

    // replace, not push: the entry being left is the landing URL. A push would
    // make Back return to a page whose only job was to spend a token that is now
    // spent, which renders as a dead link over a working session.
    router.replace("/");
  }, [isSignedIn, router]);

  if (state.status === "working") {
    return (
      <LinkStatusPanel announcement="Signing you in." title="Signing you in…">
        <p className="text-body-sm text-charcoal">This takes a moment.</p>
      </LinkStatusPanel>
    );
  }

  if (state.status === "done") {
    if (challenged) {
      return (
        <LinkStatusPanel
          announcement="This account needs a second factor."
          title="One more step"
        >
          <p className="text-body-sm text-charcoal">
            <span className="font-mono text-ink">{challenged.email}</span> is protected by
            two-factor authentication. Sign in to enter your code.
          </p>
          <p className="text-caption text-mute">
            Your link has been used. Signing in issues a fresh challenge.
          </p>
          <Button
            variant="primary"
            className="mt-sm w-full"
            onClick={() => router.replace("/sign-in")}
          >
            Continue
          </Button>
        </LinkStatusPanel>
      );
    }

    // What is on screen while the replace above resolves. The button is not
    // decoration: a navigation can be slow, and leaving a signed-in user looking
    // at a page with no way forward is worse than an extra click.
    return (
      <LinkStatusPanel announcement="You are signed in." title="Signed in">
        <p className="text-body-sm text-charcoal">Taking you to your account.</p>
        <Button variant="primary" className="mt-sm w-full" onClick={() => router.replace("/")}>
          Continue to your account
        </Button>
      </LinkStatusPanel>
    );
  }

  // As on the verification landing: a link that arrived without a token was never
  // read, so it is not reported as expired.
  const failure =
    state.status === "missing"
      ? {
          title: "This link is incomplete",
          description:
            "It arrived without a sign-in token. Copying the whole address out of the email usually fixes it.",
          remedy: "request-another" as const,
        }
      : presentLinkError(state.error, "sign-in");

  return (
    <LinkStatusPanel announcement={failure.title} title={failure.title}>
      <p className="text-body-sm text-charcoal">{failure.description}</p>

      {failure.remedy === "retry" && (
        <Button variant="primary" className="mt-sm w-full" onClick={retry}>
          Try again
        </Button>
      )}

      {/* No email field and no resend button here, unlike the verification
          landing. A magic link is a way in, so a form on this page that takes an
          address and mails a credential to it is a way in for anyone who can
          reach the page. Requesting one belongs behind the sign-in form, which
          rate-limits it. */}
      {failure.remedy === "request-another" && (
        <Button
          variant="primary"
          className="mt-sm w-full"
          onClick={() => router.push("/sign-in")}
        >
          Request a new link
        </Button>
      )}

      {failure.remedy === "contact-support" && (
        <p className="text-caption text-mute">
          Support can tell you why the account was held. A new link will not change it.
        </p>
      )}
    </LinkStatusPanel>
  );
}
