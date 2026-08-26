"use client";

import { useCallback, useState, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  AlertIcon,
  Badge,
  BuildingIcon,
  LockIcon,
  TrashIcon,
  buttonClassName,
} from "@authn/ui";
import { useAuth } from "@authn/react";
import {
  AuthnErrorCode,
  readBlockingOrganizations,
  type AuthnProfile,
  type BlockingOrganization,
} from "@authn/js";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";
import { StepUpDialog, type StepUpFactor } from "@/components/StepUpDialog";
import { useOrganizations } from "@/components/OrganizationsProvider";
import { useResource, type ResourceResult } from "@/lib/useResource";

/**
 * Authn Platform — Danger zone body
 * File: apps/web-account/src/app/account/danger/DangerCards.tsx
 *
 * The two cards in front of `DELETE /v1/client/user/account`, and the one dialog
 * that calls it.
 *
 * Two facts decide what the reader is shown, and both are read rather than assumed.
 * `hasPassword` decides which credential is asked for, because the engine checks an
 * account holding a password on its password and only one holding none falls
 * through to an authenticator code. The organization list decides whether the
 * hand-over warning applies at all — a reader who administers nothing does not need
 * to be told to hand anything over.
 *
 * The third fact only the engine has. It refuses the deletion with a 409 when the
 * account is the sole administrator of a workspace other people are still in, and
 * lists them. That refusal is a list rather than a sentence, so it is shown on the
 * card instead of inside the dialog, where there is one line for it.
 */

export function DangerCards(): ReactNode {
  const { client, isAuthenticated } = useAuth();
  const router = useRouter();
  const { organizations } = useOrganizations();

  const loadProfile = useCallback(async (): Promise<ResourceResult<AuthnProfile>> => {
    const result = await client.getProfile();
    return result.ok ? { ok: true, data: result.profile } : { ok: false, error: result.error };
  }, [client]);

  const profile = useResource(loadProfile, { enabled: isAuthenticated });

  const [isOpen, setIsOpen] = useState(false);
  /** The workspaces the engine refused over, from `error.details.organizations`. */
  const [blocking, setBlocking] = useState<BlockingOrganization[] | null>(null);

  const administered = organizations.filter((org) => org.isAdmin);

  /* Which credential the deletion is checked on. Defaulted to password while the
     profile is still loading, which is what all but a social-only or passkey-only
     account holds — and the engine's own answer arrives as a refusal naming the
     other factor if the guess is wrong. */
  const factor: StepUpFactor = profile.data?.hasPassword === false ? "totp" : "password";

  const destroy = useCallback(
    async (credential: string) => {
      const result = await client.deleteAccount(
        factor === "password" ? { password: credential } : { totpCode: credential },
      );

      if (result.ok) {
        /**
         * Sent to sign-in with a note rather than left here. The SDK has already
         * cleared the local session, so every request this page could make from now
         * on answers 401 — and a toast would be shown for a moment on a page that is
         * about to be replaced by the route guard anyway.
         */
        router.replace("/sign-in?deleted=1");
        return null;
      }

      if (result.error.code === AuthnErrorCode.CONFLICT) {
        setBlocking(readBlockingOrganizations(result.error));
        setIsOpen(false);
        /**
         * Null despite the failure, which closes the dialog. The refusal names
         * workspaces the reader has to go and act on, one per line with a link each,
         * and the dialog has room for a sentence — so the panel on the card carries
         * it and the dialog gets out of the way.
         */
        return null;
      }

      return result.error;
    },
    [client, factor, router],
  );

  return (
    <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
      {/* Both rows are things that stop being possible the moment the account goes,
          which is the only reason they come before the button rather than inside the
          dialog. The organizations row links to a page the reader can act on. */}
      <SettingsCard
        title="Before you delete"
        description="Neither of these can be done afterwards. Ten minutes now, or not at all."
      >
        <SettingsRow
          icon={BuildingIcon}
          accent="yellow"
          label="Workspaces you administer"
          value={
            administered.length === 0
              ? "None — nothing to hand over"
              : administered.length === 1
                ? "1 to hand over"
                : `${administered.length} to hand over`
          }
          hint={
            administered.length === 0
              ? "You do not administer any workspaces, so nothing is left without an administrator when your account goes. Memberships you hold are simply removed."
              : "Your memberships go with your account. Where you are the only administrator of a workspace other people are in, the deletion is refused until you grant somebody else those rights — an unadministered workspace cannot be renamed, invited to, or deleted by anyone in it."
          }
          action={
            /* An anchor and not a button. This navigates, so it should offer
               middle-click and "copy link address"; `buttonClassName` is how it looks
               like the buttons beside it without nesting one inside a link. */
            <Link
              href="/account/organizations"
              className={buttonClassName({ variant: "secondary" })}
            >
              Review organizations
            </Link>
          }
        />
        <SettingsRow
          icon={AlertIcon}
          accent="yellow"
          label="Anything you want to keep"
          value="Copy it out by hand"
          hint="There is no download to request and nothing is emailed to you afterwards. Your profile, your workspaces and your signed-in devices are all readable on the pages of this account right up to the moment you delete it."
        />
      </SettingsCard>

      <SettingsCard
        id="delete"
        title="Delete permanently"
        description="Removes the account and everything attached to it. There is no restore, no support request that reverses it, and no copy kept on our side."
        accent="red"
        action={
          <>
            <InfoHint topic="deleteAccount" label="deleting your account" position="left" />
            <Badge variant="red" dot>
              irreversible
            </Badge>
          </>
        }
        footer={
          <div className="flex w-full flex-col gap-md">
            {blocking && blocking.length > 0 ? <BlockingPanel organizations={blocking} /> : null}

            <div className="flex w-full flex-wrap items-center justify-between gap-md">
              <p className="min-w-0 flex-1 basis-[20rem] max-w-broad text-caption text-ash">
                {factor === "password"
                  ? "You will be asked for your current password. It is checked before anything is removed, so a mistyped password costs you nothing."
                  : "You will be asked for a code from your authenticator app. It is checked before anything is removed, so a mistyped code costs you nothing."}
              </p>
              <button
                type="button"
                className={buttonClassName({ variant: "destructive" })}
                onClick={() => {
                  setBlocking(null);
                  setIsOpen(true);
                }}
              >
                Delete my account
              </button>
            </div>
            <HelpText topic="deleteAccount" />
          </div>
        }
      >
        <SettingsRow
          icon={TrashIcon}
          accent="red"
          label="Removed with the account"
          value="Sessions, password, passkeys, connected accounts, guardians and memberships"
          hint="Every device signed in as you is signed out in the same moment. Authenticator apps, text-message numbers, trusted devices and recovery contacts go with it."
        />
        <SettingsRow
          icon={AlertIcon}
          accent="red"
          label="Your username"
          value="Released straight away"
          hint="The handle is free for anyone to claim as soon as the account is gone. There is no hold period, and no way to reserve it."
        />
        {/* Stated because it changes what the reader should do, not as a disclaimer: an
            account that only signs in through a connected service has no password for
            us to ask for, and the honest consequence is that an authenticator code is
            the only proof standing in front of the button. */}
        <SettingsRow
          icon={LockIcon}
          accent="red"
          label="What we check"
          value={factor === "password" ? "Your current password" : "A code from your authenticator app"}
          hint={
            factor === "password"
              ? "The password you sign in with. A social or passkey sign-in is not accepted in its place."
              : "This account has no password, so its authenticator code is the strongest proof we can ask for. Setting a password first is worth the minute it takes."
          }
        />
      </SettingsCard>

      <StepUpDialog
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        title="Delete this account permanently?"
        description="Everything attached to it goes: your profile, your sign-in methods, your devices and your memberships. Nobody can put it back, including us."
        confirmLabel="Delete it permanently"
        tone="red"
        factor={factor}
        consequence="This is the last step. There is no confirmation email and no undo window — the account is gone the moment this succeeds."
        onConfirm={destroy}
      />
    </div>
  );
}

/**
 * The workspaces standing in the way, one per line.
 *
 * Named rather than counted, and linked to their own card, because the reader has to
 * act on each one and "you administer some workspaces" does not say which. The
 * member count is what makes the refusal make sense: a workspace where they are
 * alone is deleted with the account and never appears here.
 */
function BlockingPanel({ organizations }: { organizations: BlockingOrganization[] }): ReactNode {
  return (
    <div className="flex w-full flex-col gap-sm rounded-md border border-accent-red/40 bg-accent-red/[0.06] p-md">
      <div className="flex items-start gap-sm">
        <AlertIcon variant="line" size={16} className="mt-px shrink-0 text-accent-red" />
        <p className="text-body-sm text-ink">
          Your account was not deleted. You are the only administrator of{" "}
          {organizations.length === 1 ? "a workspace" : `${organizations.length} workspaces`} other
          people are still in.
        </p>
      </div>

      <ul className="flex flex-col gap-xs">
        {organizations.map((org) => (
          <li key={org.id} className="flex flex-wrap items-center gap-sm">
            <Link
              href={`/account/organizations#${org.slug}`}
              className="text-body-sm text-ink underline decoration-hairline-strong underline-offset-2 hover:decoration-ink"
            >
              {org.name}
            </Link>
            <span className="text-caption text-ash">
              {org.otherMembers === 1 ? "1 other member" : `${org.otherMembers} other members`}
            </span>
          </li>
        ))}
      </ul>

      <p className="text-caption text-charcoal">
        Open each one, make somebody else an administrator, then try again. Deleting a
        workspace outright works too — its members lose access to it, and keep their own
        accounts.
      </p>
    </div>
  );
}
