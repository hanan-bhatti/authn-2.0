import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Button, GlobeIcon, KeyIcon, MailIcon, RingsIllustration } from "@authn/ui";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { PageHeader } from "@/components/PageHeader";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";

/**
 * Authn Platform — Connected accounts page
 * File: apps/web-account/src/app/account/connections/page.tsx
 *
 * Two lists: what is linked, and what could be. Splitting them is what makes the
 * page answerable at a glance — one list of six providers with two of them marked
 * "connected" makes the reader scan all six to find out how many are actually
 * attached, which is the only thing they came to learn.
 *
 * Which providers appear in the second list is the tenant's decision, not this
 * page's: `GET /v1/client/app-config` reports the ones configured under
 * `sign_in_methods.social_providers`, and offering any other is offering a button
 * whose redirect the engine will refuse.
 *
 * Structure and copy only: nothing here reads from
 * `GET /v1/client/user/social-accounts`, and no control is wired.
 */

export const metadata: Metadata = { title: "Connected accounts" };

export default function ConnectionsPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Connected accounts"
        description="Other services you can sign in with. Each one is a second door into this account, so a provider you no longer use is worth disconnecting."
        illustration={RingsIllustration}
        accent="blue"
      />

      <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
        <SettingsCard
          title="Connected"
          description="Signing in with one of these lands you here with no password."
          action={<InfoHint topic="socialAccounts" label="connected accounts" position="left" />}
        >
          {/* Provider, the address it reported and when it was linked. That is what a
              linked identity carries — there is no record of when one was last used to
              sign in, so the rows do not imply there is. */}
          <SettingsRow
            icon={MailIcon}
            accent="blue"
            label="Google"
            value="ada@example.com"
            hint="Connected 12 February 2026"
            action={<Button variant="secondary">Disconnect</Button>}
          />
          <SettingsRow
            icon={KeyIcon}
            accent="blue"
            label="GitHub"
            value="@adalovelace"
            hint="Connected 2 March 2026"
            action={<Button variant="secondary">Disconnect</Button>}
          />
        </SettingsCard>

        {/* Disconnecting the last provider on a passwordless account locks it, and the
            warning belongs on this page rather than in the confirmation dialog: by the
            time the dialog is open the reader has already decided. */}
        <SettingsCard
          title="Available"
          description="Connect one and it becomes another way in. You keep the same account either way."
          footer={
            <div className="flex flex-col gap-xs">
              <p className="text-caption text-ash">
                You have a password set, so disconnecting every provider still leaves you a
                way in. On an account with no password, the last provider cannot be removed.
              </p>
              <HelpText topic="socialAccounts" />
            </div>
          }
        >
          <SettingsRow
            icon={GlobeIcon}
            label="Microsoft"
            hint="Work and personal Microsoft accounts."
            action={<Button variant="secondary">Connect</Button>}
          />
          <SettingsRow
            icon={GlobeIcon}
            label="Apple"
            hint="Uses Hide My Email if you ask it to, which means we see a relay address."
            action={<Button variant="secondary">Connect</Button>}
          />
          <SettingsRow
            icon={GlobeIcon}
            label="Discord"
            hint="Signs you in with your Discord profile and its verified address."
            action={<Button variant="secondary">Connect</Button>}
          />
        </SettingsCard>
      </div>
    </>
  );
}
