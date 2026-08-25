import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Avatar, Badge, Button, IdCardIllustration } from "@authn/ui";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { PageHeader } from "@/components/PageHeader";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";

/**
 * Authn Platform — Profile page
 * File: apps/web-account/src/app/account/page.tsx
 *
 * Structure and copy only. Every value below is a placeholder: nothing on this page
 * reads from `GET /v1/client/user/profile` yet, and the controls are not wired to
 * `PATCH /v1/client/user/profile`. That is deliberate and stated rather than
 * disguised — the sidebar, the responsive frame and the illustration layer are what
 * this pass builds, and a page that looked live while showing invented data would
 * hide exactly the gap someone needs to see.
 *
 * The fields are the ones the profile DTO carries and no others. There is no time
 * zone on an account, so there is no time zone row: an input that cannot be saved
 * is worse than a missing feature, because the reader finds out only after typing.
 */

export const metadata: Metadata = { title: "Profile" };

export default function ProfilePage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Profile"
        description="Your name, your handle, and the address we use to reach you. This is what other people see when you join an organization."
        illustration={IdCardIllustration}
        accent="blue"
      />

      <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
        {/* Each row saves itself, so there is no page-level "save changes". One save
            button over three independently editable rows cannot say which of them it
            is about to write, and the reader cannot tell whether an edit they made
            two rows ago is still pending. */}
        <SettingsCard title="Identity" description="How you appear across Authn.">
          <SettingsRow
            label="Avatar"
            value="Generated from your initials"
            hint="Point us at an image on the web and we will show it here. There is nowhere to upload a file yet."
            action={
              <>
                <Avatar size="lg" name="Ada Lovelace" />
                <Button variant="secondary">Set image URL</Button>
              </>
            }
          />
          <SettingsRow
            label="Display name"
            value="Ada Lovelace"
            hint="Shown on invitations and in member lists."
            action={<Button variant="secondary">Edit</Button>}
          />
          {/* The handle is the one field on this page that is globally unique, which is
              why it gets a claim state rather than a plain value. */}
          <SettingsRow
            label="Username"
            value="@ada"
            hint="3 to 30 characters. Letters, digits and underscores only, starting with a letter. You can sign in with it instead of your email."
            action={
              <>
                <Badge variant="green">claimed</Badge>
                <InfoHint topic="username" label="usernames" />
                <Button variant="secondary">Change</Button>
              </>
            }
          />
        </SettingsCard>

        <SettingsCard
          title="Email"
          description="Where verification links, security notices and magic links are sent."
          footer={<HelpText topic="emailChange" />}
        >
          <SettingsRow
            label="Primary email"
            value="ada@example.com"
            hint="Used to sign in. Changing it needs the new address confirmed before anything moves."
            action={
              <>
                <Badge variant="green">verified</Badge>
                <InfoHint topic="emailChange" label="changing your email" />
                <Button variant="secondary">Change</Button>
              </>
            }
          />
          <SettingsRow
            label="Recovery email"
            value="Not set"
            hint="A second address on your account, confirmed by a link. It is never used to sign in."
            action={
              <>
                <InfoHint topic="recoveryEmail" label="the recovery email" />
                <Button variant="secondary">Add</Button>
              </>
            }
          />
        </SettingsCard>

        <SettingsCard
          title="Preferences"
          description="Applied to the language of the emails we send."
        >
          <SettingsRow
            label="Language"
            value="English (United Kingdom)"
            hint="A language tag such as en-GB. It travels with your account, so it is the same wherever you sign in."
            action={<Button variant="secondary">Change</Button>}
          />
        </SettingsCard>
      </div>
    </>
  );
}
