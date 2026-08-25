import type { Metadata } from "next";
import type { ReactNode } from "react";
import { BuildingIcon, Button, MailIcon, NodeTreeIllustration, UsersIcon } from "@authn/ui";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { PageHeader } from "@/components/PageHeader";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";

/**
 * Authn Platform — Organizations page
 * File: apps/web-account/src/app/account/organizations/page.tsx
 *
 * One card per organization, and the card ids are the sidebar's children. What
 * belongs on *this* page is only the part that is about the reader: which
 * organizations they are in, when they joined, and the controls the engine will
 * accept from them.
 *
 * `GET /v1/client/organizations` returns name, slug and creation date and nothing
 * more — no member count, no role — so the counts in each description come from
 * `GET /organizations/:orgId/members` and `/invitations`, both readable by any
 * member. There is one privileged tier, the `org_admin` role, and its name cannot
 * be reached from a client session: `GET /v1/tenant/roles` needs a secret key and
 * `OrgMemberResponse` carries `role_id` alone. So no card claims a tier. The rows
 * state the rule instead, which is true for every reader.
 *
 * Structure and copy only: nothing here reads from the engine, and no control is
 * wired.
 */

export const metadata: Metadata = { title: "Organizations" };

export default function OrganizationsPage(): ReactNode {
  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Organizations"
        description="The shared workspaces this account belongs to. Each one has its own members and roles; your account exists on its own, so losing access to a workspace does not affect it."
        illustration={NodeTreeIllustration}
        accent="blue"
        actions={<Button variant="primary">Create an organization</Button>}
      />

      <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
        <SettingsCard
          id="acme"
          title="Acme Inc"
          description="acme · 24 members · Created 4 January 2026"
          action={<InfoHint topic="organizations" label="organizations" position="left" />}
          footer={
            <div className="flex w-full flex-wrap items-center justify-between gap-md">
              <div className="min-w-0 flex-1 basis-[20rem]">
                <HelpText topic="organizations" />
              </div>
              <Button variant="destructive">Delete organization</Button>
            </div>
          }
        >
          <SettingsRow
            icon={UsersIcon}
            accent="blue"
            label="Members"
            value="24 members"
            hint="Everyone here can see who else is. Inviting someone, changing a role or removing a member needs organization-admin rights."
            action={<Button variant="secondary">Invite someone</Button>}
          />
          {/* The count, not the list. Every invitation carries the address it was sent
              to, and that is somebody's email address shown to everyone in the
              workspace — the list belongs behind the control that can also revoke
              them, where the reader has a reason to be looking at it. */}
          <SettingsRow
            icon={MailIcon}
            accent="blue"
            label="Pending invitations"
            value="2 waiting"
            hint="Each one expires on its own schedule — seven days unless whoever sent it chose a different window. Revoking one takes effect immediately."
          />
          <SettingsRow
            icon={BuildingIcon}
            accent="blue"
            label="Name and slug"
            value="Acme Inc · acme"
            hint="The slug is the URL-safe form of the name and has to be unique in your tenant. It appears in links, so changing it can break ones already shared."
            action={<Button variant="secondary">Rename</Button>}
          />
        </SettingsCard>

        {/* Removing a member needs organization-admin rights even when the member is
            you, so there is no "leave" button on this card: a button that answers 403
            for most of the people who press it teaches them less than one sentence
            saying who to ask. */}
        <SettingsCard
          id="northwind"
          title="Northwind"
          description="northwind-trading · 6 members · Created 18 February 2026"
          action={<InfoHint topic="organizations" label="organizations" position="left" />}
          footer={
            <p className="text-caption text-ash">
              Removing a member — including yourself — needs organization-admin rights. To
              leave a workspace you do not administer, ask an administrator there to remove
              you.
            </p>
          }
        >
          <SettingsRow
            icon={UsersIcon}
            accent="blue"
            label="Members"
            value="6 members"
            hint="Visible to everyone in the workspace. Changing who is in it needs organization-admin rights."
          />
          <SettingsRow
            icon={BuildingIcon}
            label="You joined"
            value="20 February 2026"
            hint="Your membership records when it was created and who granted it."
          />
        </SettingsCard>

        {/* An invitation reaches you by email and nowhere else: no endpoint lists
            invitations addressed to the signed-in reader, only ones addressed to an
            organization they already belong to. So this card is the redemption control
            — `POST /v1/client/invitations/accept` with the token from the email —
            rather than an inbox that would always look empty. */}
        <SettingsCard
          id="invitations"
          title="Accept an invitation"
          description="An invitation arrives by email. Open the link in it, or paste the code here."
          action={<InfoHint topic="invitations" label="invitations" position="left" />}
          footer={
            <div className="flex flex-col gap-xs">
              <p className="text-caption text-ash">
                An invitation you have not opened will not appear on this page — the email
                is the only copy, so search your inbox for it rather than waiting here.
              </p>
              <HelpText topic="invitations" />
            </div>
          }
        >
          <SettingsRow
            icon={MailIcon}
            accent="blue"
            label="Invitation code"
            value="From the email we sent you"
            hint="Single-use, and it expires with the invitation — seven days unless whoever sent it chose a different window. Accepting it adds you to the workspace with the role they picked."
            action={<Button variant="primary">Accept invitation</Button>}
          />
        </SettingsCard>
      </div>
    </>
  );
}
