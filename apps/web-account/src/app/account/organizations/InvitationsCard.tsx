"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { AlertIcon, Badge, Button, Input, MailIcon, useToast } from "@authn/ui";
import { useAuth } from "@authn/react";
import type { AuthnOrgInvitation } from "@authn/js";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { LoadError, RowSkeleton } from "@/components/CardState";
import { SettingsCard } from "@/components/SettingsCard";
import { presentSaveError } from "@/lib/authError";
import { formatUntil } from "@/lib/datetime";
import { useResource, type ResourceResult } from "@/lib/useResource";

/**
 * Authn Platform — Invitations addressed to the reader
 * File: apps/web-account/src/app/account/organizations/InvitationsCard.tsx
 *
 * The workspaces somebody has asked this account to join, and the field that joins
 * one.
 *
 * The list and the field are separate on purpose, and it is the engine that makes
 * them so. `GET /v1/client/invitations` finds invitations by the account's verified
 * address but never returns their redemption tokens — only the administrator who
 * created an invitation is ever shown its token. So the list can say an invitation
 * exists and cannot accept it; accepting needs the code from the email, pasted in.
 *
 * The field is therefore always available, not only when the list has something in
 * it. An invitation sent to an address that is not this account's primary one does
 * not appear in the list at all, and its code still works.
 */

export interface InvitationsCardProps {
  /** Reloads the page's organizations after one is joined. */
  onAccepted: () => Promise<void>;
}

/**
 * Where an invitation code waits between arriving in a link and being redeemed.
 *
 * Namespaced because session storage is shared with everything else this origin
 * runs, and prefixed with the app rather than the page so a second place that
 * learns to accept invitations reads the same one.
 */
const PENDING_INVITE_KEY = "authn.pending-invite";

export function InvitationsCard({ onAccepted }: InvitationsCardProps): ReactNode {
  const { client, isAuthenticated, user } = useAuth();

  /**
   * Whether the empty inbox is empty because nothing was sent, or because the
   * engine is withholding what was.
   *
   * Read from the session rather than the profile endpoint, since the session
   * already carries it and one more request would only confirm what is on screen in
   * the sidebar. Undefined while the probe is in flight, which reads as verified —
   * the milder of the two, and the flag settles before the list does.
   */
  const isUnverified = user !== null && user.emailVerified === false;
  const toast = useToast();

  const load = useCallback(async (): Promise<ResourceResult<AuthnOrgInvitation[]>> => {
    const result = await client.listInvitations();
    return result.ok ? { ok: true, data: result.invitations } : { ok: false, error: result.error };
  }, [client]);

  const invitations = useResource(load, { enabled: isAuthenticated });

  const [code, setCode] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [isJoining, setIsJoining] = useState(false);

  /**
   * Fills the field from `?invite=`, then takes the code out of the address bar.
   *
   * The link an administrator copies carries the code, so arriving by it should not
   * mean re-typing 64 hex characters. Removing it afterwards is the other half:
   * until it is redeemed the code is a credential, and one left in the URL is in the
   * history, in the title bar, and in whatever the reader pastes next.
   *
   * The two halves cannot both work through state alone, which is why session
   * storage sits between them. Stripping the parameter destroys the only copy, so a
   * component that mounts a second time finds an address bar with nothing in it and
   * a field it has just emptied — and mounting twice is not exotic: React does it to
   * every component in development on purpose. Storage is read on every mount,
   * including the first, so the field survives it.
   *
   * Tab-scoped, so a code pasted in one tab does not turn up in another, and gone as
   * soon as the invitation is redeemed.
   *
   * Read from `window` rather than through `useSearchParams`, which would make this
   * page's prerender depend on a search parameter and need a Suspense boundary
   * around it to say nothing more than this effect does.
   */
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const fromLink = params.get("invite");

    if (fromLink !== null && fromLink !== "") {
      window.sessionStorage.setItem(PENDING_INVITE_KEY, fromLink);
      params.delete("invite");
      const query = params.toString();
      window.history.replaceState(
        null,
        "",
        `${window.location.pathname}${query === "" ? "" : `?${query}`}${window.location.hash}`,
      );
    }

    const pending = window.sessionStorage.getItem(PENDING_INVITE_KEY);
    if (pending !== null && pending !== "") setCode(pending);
  }, []);

  const accept = useCallback(async () => {
    const token = code.trim();
    if (token === "") {
      setMessage("Paste the code from your invitation email.");
      return;
    }

    setIsJoining(true);
    setMessage(null);
    const result = await client.acceptOrgInvitation({ invitationToken: token });
    setIsJoining(false);

    if (!result.ok) {
      /* A code the engine has turned down on its merits — expired, already used,
         addressed to somebody else — is not worth restoring on the next reload. One
         turned down by a dropped connection is, and the field still holds it either
         way for an immediate retry. */
      if (!result.error.isRetryable) window.sessionStorage.removeItem(PENDING_INVITE_KEY);
      setMessage(presentSaveError(result.error, "invitation"));
      return;
    }

    window.sessionStorage.removeItem(PENDING_INVITE_KEY);
    setCode("");
    void invitations.refetch();
    await onAccepted();
    toast.success(
      "You have joined the workspace",
      "It is in the list above and in the sidebar. What you can do there depends on the role you were given.",
    );
  }, [client, code, invitations, onAccepted, toast]);

  return (
    <SettingsCard
      title="Invitations"
      description="Workspaces somebody has asked you to join. Accepting one adds you to it; it does not change your account."
      action={<InfoHint topic="invitations" label="invitations" position="left" />}
      footer={<HelpText topic="invitations" />}
    >
      {invitations.isLoading ? (
        <RowSkeleton rows={1} label="your invitations" />
      ) : !invitations.data ? (
        <LoadError
          label="your invitations"
          message={invitations.error?.message}
          onRetry={() => void invitations.refetch()}
          isRetrying={invitations.isRefetching}
        />
      ) : invitations.data.length === 0 ? (
        isUnverified ? (
          /* An unverified address reads as an empty inbox, and the reason is not
             guessable from the outside: the engine withholds invitations addressed
             to an address nobody has proved they hold, so that registering as
             somebody else's address does not hand over what was sent to it. Left
             unsaid, this is somebody staring at "nothing is waiting for you" with an
             invitation in their email. */
          <div className="flex items-start gap-sm p-lg">
            <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-accent-orange" />
            <div className="flex flex-col gap-xxs">
              <p className="text-body-sm text-ink">
                Verify your email address to see invitations sent to it.
              </p>
              <p className="text-caption text-charcoal">
                We hold them back until then, so that registering an address nobody
                has proved they hold cannot reveal what was sent to it. Confirm{" "}
                {user?.email ?? "your address"} from{" "}
                <Link href="/account/profile" className="text-ink underline">
                  your profile
                </Link>{" "}
                and they will appear here. A code you already have works below either
                way.
              </p>
            </div>
          </div>
        ) : (
          <p className="p-lg text-body-sm text-ash">
            Nothing is waiting for you. An invitation sent to a different address than your
            account&rsquo;s will not appear here, but its code still works below.
          </p>
        )
      ) : (
        invitations.data.map((invitation) => (
          <div
            key={invitation.id}
            className="flex flex-wrap items-center justify-between gap-md p-lg not-first:border-t not-first:border-hairline"
          >
            <div className="flex min-w-0 flex-1 basis-[16rem] flex-col gap-xxs">
              <span className="truncate text-body-sm text-ink">
                {invitation.organizationName ?? "An organization"}
              </span>
              <span className="text-caption text-ash">
                Sent to {invitation.email} · Expires {formatUntil(invitation.expiresAt)}
              </span>
            </div>
            {/* A badge and not a button. The token is not in this payload, so a button
                here would have nothing to send — which is why the field below exists. */}
            <Badge variant="yellow" size="sm" dot>
              code is in your email
            </Badge>
          </div>
        ))
      )}

      <div className="flex flex-col gap-md p-lg not-first:border-t not-first:border-hairline">
        <div className="flex flex-col gap-xxs">
          <span className="text-body-sm text-ink">Join with an invitation code</span>
          <span className="text-caption text-ash">
            The long code in your invitation email, or the link the person who invited you
            sent.
          </span>
        </div>

        <form
          noValidate
          className="flex flex-wrap items-start gap-sm"
          onSubmit={(event) => {
            event.preventDefault();
            void accept();
          }}
        >
          {/* Grows from a fixed basis rather than filling the row, so the button sits
              beside it on a laptop and under it on a phone instead of being squeezed
              to the width of its own label. */}
          <div className="min-w-0 flex-1 basis-[18rem]">
            <Input
              value={code}
              placeholder="Paste your invitation code"
              autoComplete="off"
              isMonospace
              disabled={isJoining}
              leftIcon={<MailIcon size={14} />}
              onChange={(event) => {
                setCode(event.target.value);
                setMessage(null);
              }}
            />
          </div>
          <Button type="submit" variant="primary" isLoading={isJoining}>
            Join
          </Button>
        </form>

        {message ? <p className="text-body-sm text-accent-red">{message}</p> : null}
      </div>
    </SettingsCard>
  );
}
