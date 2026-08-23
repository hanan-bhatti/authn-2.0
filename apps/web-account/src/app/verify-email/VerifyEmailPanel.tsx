"use client";

/**
 * Authn Platform — Email verification panel
 * File: apps/web-account/src/app/verify-email/VerifyEmailPanel.tsx
 */

import { useCallback, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@authn/ui";
import { useAuth } from "@authn/react";
import type { AuthnError } from "@authn/js";
import { LinkStatusPanel } from "@/components/LinkStatusPanel";
import { presentLinkError } from "@/lib/linkError";
import { useEmailedToken } from "@/lib/useEmailedToken";

/** How a request for a replacement link ended, once it has. */
type ResendState = { kind: "idle" } | { kind: "sending" } | { kind: "sent" } | { kind: "failed" };

export function VerifyEmailPanel({ token }: { token: string | undefined }): ReactNode {
  const { client, user } = useAuth();
  const router = useRouter();
  const [resend, setResend] = useState<ResendState>({ kind: "idle" });

  const redeem = useCallback(
    async (value: string) => {
      try {
        return await client.verifyEmail({ token: value });
      } catch (err) {
        // verifyEmail validates the token before opening its own try block, so a
        // token the SDK rejects outright arrives as a throw rather than as a
        // result. Both mean the same thing to this page.
        return { ok: false as const, error: err as AuthnError };
      }
    },
    [client],
  );

  const { state, retry } = useEmailedToken(token, redeem);

  // Only available when the browser already holds a session — the user signed up
  // in this tab, or is signed in and verifying a second time. A click from a mail
  // client in a fresh browser has no session and so no address to send to, which
  // is why the fallback is a sign-in link rather than an email field: asking for
  // an address here would let anyone probe which ones exist.
  const knownEmail = user?.email;

  const requestAnother = useCallback(async () => {
    if (!knownEmail) return;
    setResend({ kind: "sending" });
    const result = await client.resendVerification({ email: knownEmail });
    setResend(result.ok ? { kind: "sent" } : { kind: "failed" });
  }, [client, knownEmail]);

  if (state.status === "working") {
    return (
      <LinkStatusPanel announcement="Verifying your email address." title="Verifying…">
        <p className="text-body-sm text-charcoal">This takes a moment.</p>
      </LinkStatusPanel>
    );
  }

  if (state.status === "done") {
    return (
      <LinkStatusPanel announcement="Your email address is verified." title="Email verified">
        <p className="text-body-sm text-charcoal">
          {user?.email ? (
            <>
              <span className="font-mono text-ink">{user.email}</span> is confirmed. Your account is
              ready.
            </>
          ) : (
            <>Your address is confirmed. Sign in to use your account.</>
          )}
        </p>

        {/* A push rather than a styled anchor, for the same reason as sign-up's
            confirmation: copying the primary button's classes onto a Link is how a
            design system drifts. */}
        <Button
          variant="primary"
          className="mt-sm w-full"
          onClick={() => router.push(user ? "/" : "/sign-in")}
        >
          {user ? "Continue to your account" : "Sign in"}
        </Button>
      </LinkStatusPanel>
    );
  }

  // A link that arrived without a token at all. Nothing was attempted, so this is
  // not reported as a refusal — the remedy is the same, but "expired" would be a
  // guess about a link that was never read.
  const failure =
    state.status === "missing"
      ? {
          title: "This link is incomplete",
          description:
            "It arrived without a verification token. Copying the whole address out of the email usually fixes it.",
          remedy: "request-another" as const,
        }
      : presentLinkError(state.error, "verification");

  return (
    <LinkStatusPanel announcement={failure.title} title={failure.title}>
      <p className="text-body-sm text-charcoal">{failure.description}</p>

      {failure.remedy === "retry" && (
        <Button variant="primary" className="mt-sm w-full" onClick={retry}>
          Try again
        </Button>
      )}

      {failure.remedy === "request-another" &&
        (knownEmail ? (
          <ResendControl email={knownEmail} state={resend} onSend={() => void requestAnother()} />
        ) : (
          <p className="text-caption text-mute">
            Sign in and we will send a new link — an unverified account can still ask for one.{" "}
            <Link
              href="/sign-in"
              className="text-ink underline decoration-hairline-strong underline-offset-2 hover:decoration-ink"
            >
              Sign in
            </Link>
          </p>
        ))}

      {failure.remedy === "contact-support" && (
        <p className="text-caption text-mute">
          Support can tell you why the account was held. A new link will not change it.
        </p>
      )}
    </LinkStatusPanel>
  );
}

function ResendControl({
  email,
  state,
  onSend,
}: {
  email: string;
  state: ResendState;
  onSend: () => void;
}): ReactNode {
  if (state.kind === "sent") {
    return (
      <p className="text-body-sm text-charcoal">
        A new link is on its way to <span className="font-mono text-ink">{email}</span>.
      </p>
    );
  }

  return (
    <>
      <Button
        variant="primary"
        className="mt-sm w-full"
        isLoading={state.kind === "sending"}
        onClick={onSend}
      >
        Send a new link
      </Button>

      {state.kind === "failed" && (
        // Deliberately vague about the cause. The likely one is the engine's own
        // throttle on resends, and naming it invites a user to sit and retry
        // against a limit whose window this page does not know.
        <p className="text-caption text-accent-red">
          That did not go through. Wait a moment and try once more.
        </p>
      )}
    </>
  );
}
