"use client";

/**
 * Authn Platform — Guardian invitation acceptance panel
 * File: apps/web-account/src/app/recovery/guardian/accept/GuardianAcceptPanel.tsx
 *
 * Unlike the other two emailed-link landings this one does not redeem on mount, and
 * that is deliberate rather than an omission. Verifying your own address confirms
 * something you already asked for; agreeing to be a guardian is a commitment made on
 * someone else's behalf, and these links travel through whatever channel the account
 * holder happens to use — several of which fetch a URL in a real headless browser to
 * build a preview. An automatic acceptance would enrol a guardian who never read the
 * page, and the account holder would believe they were protected.
 */

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { AlertIcon, Button, CopyButton, InfoIcon, ShieldCheckIcon } from "@authn/ui";
import { AuthnErrorCode, type AuthnError } from "@authn/js";
import { useAuth } from "@authn/react";
import { LinkStatusPanel } from "@/components/LinkStatusPanel";

/** The two halves of the link, both read from the fragment. */
interface Secrets {
  token: string;
  share: string;
}

/**
 * Where the page has got to.
 *
 * `incomplete` is separate from `failed` because nothing was sent: a link that lost
 * part of its address is a different problem from one the engine refused, and the
 * guardian can often fix it themselves by opening the original again.
 */
type Phase =
  | { kind: "reading" }
  | { kind: "incomplete" }
  | { kind: "ready"; secrets: Secrets }
  | { kind: "sending"; secrets: Secrets }
  | { kind: "accepted"; secrets: Secrets; wasAlreadyActive: boolean }
  | { kind: "failed"; error: AuthnError };

/** What the page says about a refusal, and whether the same attempt is worth repeating. */
interface AcceptFailure {
  title: string;
  description: string;
  canRetry: boolean;
}

/**
 * Turns a refusal into copy for this page.
 *
 * Written here rather than routed through `presentLinkError` because every remedy that
 * helper offers is one this reader cannot perform. They have no account to sign in to
 * and no way to ask the engine for another link: only the account holder can issue one,
 * so each message below ends by pointing back at that person.
 */
function presentAcceptFailure(error: AuthnError): AcceptFailure {
  switch (error.code) {
    // An expired invitation, or a token that does not match the one issued. The engine
    // distinguishes them; this page does not, because both end at the same request and
    // separating them would tell anyone holding a stolen link which half was wrong.
    case AuthnErrorCode.UNAUTHORIZED:
      return {
        title: "This link no longer works",
        description:
          "Guardian invitations expire after 7 days, and each one works for a single invitation. Ask the person who invited you to send a new link.",
        canRetry: false,
      };

    case AuthnErrorCode.NOT_FOUND:
      return {
        title: "This invitation no longer exists",
        description:
          "It was most likely withdrawn. If you still want to help, ask the person who invited you to add you again.",
        canRetry: false,
      };

    // The engine's `validation_failed`, which on this route means the share in the
    // fragment did not match the one the invitation was issued with. In practice the
    // address was cut short somewhere between their message and this tab.
    case AuthnErrorCode.VALIDATION_ERROR:
    case AuthnErrorCode.INVALID_PARAMS:
      return {
        title: "This link is incomplete",
        description:
          "Part of the address was cut off, which happens when a long link is wrapped by a chat app or copied by hand. Open the original link again, all of it — or ask for a new one.",
        canRetry: false,
      };

    case AuthnErrorCode.RATE_LIMITED:
      return {
        title: "Too many attempts",
        description: "Wait a minute, then try again.",
        canRetry: true,
      };

    case AuthnErrorCode.NETWORK_ERROR:
    case AuthnErrorCode.TIMEOUT:
    case AuthnErrorCode.CANCELLED:
      return {
        title: "Could not reach the server",
        // Nothing was accepted, so the link is untouched and the same one will work.
        description: "Your link is still valid. Check your connection and try again.",
        canRetry: true,
      };

    case AuthnErrorCode.SERVER_ERROR:
      return {
        title: "Something went wrong on our side",
        description: "This is usually temporary. Try again in a moment.",
        canRetry: true,
      };

    default:
      return {
        title: "Could not add you as a guardian",
        description: error.isRetryable
          ? "Try again in a moment."
          : "Ask the person who invited you to send a new link.",
        canRetry: error.isRetryable,
      };
  }
}

/**
 * Reads both secrets out of the current address bar.
 *
 * The fragment is deliberately never removed afterwards. The query token on the other
 * two landings is stripped the moment it is used, because it is spent and still leaks
 * through history and the `Referer` header — but a fragment is never sent anywhere, and
 * this one carries the guardian's share, which they are supposed to keep. Clearing it
 * would destroy the only copy of the credential this page exists to hand over.
 */
function readFragment(): Phase {
  const values = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const token = values.get("token") ?? "";
  const share = values.get("share") ?? "";
  return token && share ? { kind: "ready", secrets: { token, share } } : { kind: "incomplete" };
}

export function GuardianAcceptPanel({ contactId }: { contactId: string | undefined }): ReactNode {
  const { client } = useAuth();
  const [phase, setPhase] = useState<Phase>({ kind: "reading" });

  // In an effect because `window` does not exist while this renders on the server, and
  // read once: the fragment is not state that anything else changes.
  useEffect(() => {
    setPhase(contactId ? readFragment() : { kind: "incomplete" });
  }, [contactId]);

  const accept = useCallback(async () => {
    if (!contactId || phase.kind !== "ready") return;
    const { secrets } = phase;
    setPhase({ kind: "sending", secrets });

    let result: { ok: true } | { ok: false; error: AuthnError };
    try {
      result = await client.acceptGuardianInvite({ contactId, ...secrets });
    } catch (err) {
      // The SDK checks its arguments before opening its own try block, so anything it
      // rejects outright arrives as a throw rather than as a result.
      result = { ok: false, error: err as AuthnError };
    }

    if (result.ok) {
      setPhase({ kind: "accepted", secrets, wasAlreadyActive: false });
      return;
    }

    // The engine's `already_exists`, which the SDK maps onto EMAIL_ALREADY_EXISTS for
    // every route — the name is about sign-up, where that code has its own remedy.
    // Here it means this guardian is already active, which is not a failure: the usual
    // cause is someone reopening their own link to find their share again, and what
    // they came for is the screen below.
    if (result.error.code === AuthnErrorCode.EMAIL_ALREADY_EXISTS) {
      setPhase({ kind: "accepted", secrets, wasAlreadyActive: true });
      return;
    }

    setPhase({ kind: "failed", error: result.error });
  }, [client, contactId, phase]);

  // Only offered after a transport failure, where nothing reached the engine and the
  // link is therefore untouched. Re-reading the fragment is the whole retry: it was
  // never cleared, so the same secrets are still there.
  const retry = useCallback(() => setPhase(readFragment()), []);

  if (phase.kind === "reading") {
    return (
      <LinkStatusPanel announcement="Reading your invitation." title="Checking your link…">
        <p className="text-body-sm text-charcoal">This takes a moment.</p>
      </LinkStatusPanel>
    );
  }

  if (phase.kind === "incomplete") {
    return (
      <LinkStatusPanel announcement="This invitation link is incomplete." title="This link is incomplete">
        <p className="text-body-sm text-charcoal">
          Part of the address is missing, so there is nothing here to accept. Long links
          are often wrapped or shortened in transit — open the one you were sent again,
          from the first character to the last.
        </p>
        <p className="text-caption text-mute">
          If that does not work, ask the person who invited you to send a new link.
        </p>
      </LinkStatusPanel>
    );
  }

  if (phase.kind === "accepted") {
    return <SavedShare share={phase.secrets.share} wasAlreadyActive={phase.wasAlreadyActive} />;
  }

  if (phase.kind === "failed") {
    const failure = presentAcceptFailure(phase.error);
    return (
      <LinkStatusPanel announcement={failure.title} title={failure.title}>
        <p className="text-body-sm text-charcoal">{failure.description}</p>
        {failure.canRetry && (
          <Button variant="primary" className="mt-sm w-full" onClick={retry}>
            Try again
          </Button>
        )}
      </LinkStatusPanel>
    );
  }

  const isSending = phase.kind === "sending";

  return (
    <LinkStatusPanel
      announcement="You have been asked to be a recovery guardian."
      title="Be a recovery guardian"
    >
      <p className="text-body-sm text-charcoal">
        Guardians are the people an account falls back on when every other way in is
        gone — no password, no phone, no codes. Nothing happens until that person asks
        for help.
      </p>

      <ul className="flex flex-col gap-md">
        <Point icon={<ShieldCheckIcon variant="line" size={16} className="text-accent-green" />}>
          <span className="text-ink">If they are ever locked out</span>, they will ask you for
          a code — one we give you on the next screen, and which you keep. More than half of
          their guardians have to agree before the account can be recovered, so no single
          person, including you, can do it alone.
        </Point>

        <Point icon={<InfoIcon variant="line" size={16} className="text-accent-blue" />}>
          <span className="text-ink">You do not get access to their account.</span> You
          cannot sign in as them, read anything of theirs, or change any of their settings.
          Accepting adds nothing to your own account and does not create one.
        </Point>

        <Point icon={<AlertIcon variant="line" size={16} className="text-accent-yellow" />}>
          <span className="text-ink">If you do not know who sent you this link</span>, close
          this page. Accepting an invitation from a stranger is agreeing to help them into
          an account that may not be theirs.
        </Point>
      </ul>

      <Button variant="primary" className="mt-sm w-full" isLoading={isSending} onClick={() => void accept()}>
        I agree to be a guardian
      </Button>
    </LinkStatusPanel>
  );
}

/** One item in the what-this-means list: a fixed-width icon gutter and prose beside it. */
function Point({ icon, children }: { icon: ReactNode; children: ReactNode }): ReactNode {
  return (
    <li className="flex items-start gap-sm">
      <span className="mt-px shrink-0">{icon}</span>
      <span className="text-body-sm text-charcoal">{children}</span>
    </li>
  );
}

/**
 * The screen the whole page builds towards: the guardian's share, and what to do with it.
 *
 * This is the only place the share is ever shown by the product. The engine keeps a
 * SHA-256 digest of it and nothing else, so it cannot be looked up, resent, or recovered
 * — a guardian who leaves without it is enrolled but useless, and the failure would only
 * surface during a lockout, the one moment it cannot be fixed.
 */
function SavedShare({
  share,
  wasAlreadyActive,
}: {
  share: string;
  wasAlreadyActive: boolean;
}): ReactNode {
  return (
    <LinkStatusPanel
      announcement={
        wasAlreadyActive
          ? "You are already a guardian. Save your recovery code."
          : "You are now a guardian. Save your recovery code."
      }
      title={wasAlreadyActive ? "You are already a guardian" : "You are a guardian"}
    >
      <p className="text-body-sm text-charcoal">
        {wasAlreadyActive
          ? "You accepted this invitation already, so nothing changed. Your code is below, in case you came back for it."
          : "Thank you. There is one thing left, and it is the part that makes any of this work."}
      </p>

      <div className="flex flex-col gap-sm">
        <span className="text-caption text-mute uppercase tracking-wide font-mono">
          Your guardian code
        </span>
        <div className="flex flex-wrap items-center gap-sm">
          {/* `break-all` and `select-all`: 64 hex characters wrap badly and are worse to
              select by hand, and a reader comparing this against a saved copy needs to
              see all of it rather than an ellipsis. */}
          <code className="min-w-0 flex-1 basis-[16rem] break-all rounded-sm bg-surface-card px-sm py-xs font-mono text-caption text-charcoal select-all">
            {share}
          </code>
          <CopyButton value={share} label="Copy code" />
        </div>
      </div>

      <div className="flex items-start gap-sm rounded-md border border-accent-yellow/40 bg-accent-yellow/8 p-md">
        <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-accent-yellow" />
        <p className="text-caption text-charcoal">
          Save it somewhere you will still have it in a year — a password manager is
          ideal. We store only a fingerprint of this code, never the code itself, so
          nobody can send it to you again. Keeping this link works too: the code is part
          of the address.
        </p>
      </div>

      <p className="text-caption text-mute">
        Give it to nobody but the person who invited you, and only once you are sure it is
        really them asking. Anyone holding your code can use it in your place.
      </p>
    </LinkStatusPanel>
  );
}
