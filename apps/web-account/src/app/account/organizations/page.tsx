import type { Metadata } from "next";
import type { ReactNode } from "react";
import { NodeTreeIllustration } from "@authn/ui";
import { PageHeader } from "@/components/PageHeader";
import { CreateOrganizationButton, OrganizationCards } from "./OrganizationCards";

/**
 * Authn Platform — Organizations page
 * File: apps/web-account/src/app/account/organizations/page.tsx
 *
 * One card per organization, anchored on the slug so the sidebar's workspace rows
 * have somewhere to land. What belongs on *this* page is the part that is about the
 * reader: which workspaces they are in, what they may do in each, and the two exits
 * — leaving, and deleting one they administer.
 *
 * Everything the cards need arrives in three reads. The list itself comes from the
 * provider around this segment, shared with the sidebar so the tree and the cards
 * cannot disagree. `isAdmin` on each entry decides which controls are drawn, and it
 * is the same answer the mutating endpoints give — which is what makes hiding a
 * control on it honest rather than optimistic. Members and outstanding invitations
 * are read per workspace, inside the dialog that acts on them.
 *
 * The header is server-rendered and the cards are not, with one exception: the
 * create button opens a dialog, so it is a client component passed in as an action.
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
        actions={<CreateOrganizationButton />}
      />

      <OrganizationCards />
    </>
  );
}
