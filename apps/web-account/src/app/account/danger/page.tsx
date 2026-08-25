import type { Metadata } from "next";
import type { ReactNode } from "react";
import {
  AlertIcon,
  Badge,
  BuildingIcon,
  Button,
  LockIcon,
  ShredderIllustration,
  TrashIcon,
} from "@authn/ui";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { PageHeader } from "@/components/PageHeader";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";

/**
 * Authn Platform — Danger zone
 * File: apps/web-account/src/app/account/danger/page.tsx
 *
 * The whole page exists to slow one request down. `DELETE /v1/client/user/account`
 * is the only thing the engine offers here — there is no export and no
 * deactivation, so nothing on this page suggests either. What stands in front of
 * the button instead is the pair of consequences the reader cannot see from where
 * they are standing: their memberships go with them, and nothing is recoverable
 * afterwards.
 *
 * The one page in the account with a full-strength accent on its illustration, and
 * the one card with the accent on its border rather than a hairline. A reader
 * skimming identically framed cards has been given no signal which one is
 * different in kind.
 *
 * Structure and copy only: nothing here reads from the engine, and no control is
 * wired — deliberately, since the wired version of this page destroys an account.
 */

export const metadata: Metadata = { title: "Delete account" };

export default function DangerPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Delete account"
        description="One request, and it cannot be taken back. Two things are worth settling before you make it."
        illustration={ShredderIllustration}
        accent="red"
      />

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
            value="Hand them over first"
            hint="Your memberships go with your account. If you are the only administrator of a workspace, deleting your account leaves it with nobody who can invite, remove or rename anything."
            action={<Button variant="secondary">Review organizations</Button>}
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
              <div className="flex w-full flex-wrap items-center justify-between gap-md">
                <p className="min-w-0 flex-1 basis-[20rem] max-w-broad text-caption text-ash">
                  You will be asked for your current password. It is checked before anything
                  is removed, so a mistyped password costs you nothing.
                </p>
                <Button variant="destructive">Delete my account</Button>
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
              us to ask for, and the honest consequence is that this session is the only
              proof standing in front of the button. */}
          <SettingsRow
            icon={LockIcon}
            accent="red"
            label="What we check"
            value="Your current password"
            hint="If you have no password — you only sign in through a connected service — this session is the only proof we can ask for. Setting a password first is worth the minute it takes."
          />
        </SettingsCard>
      </div>
    </>
  );
}
