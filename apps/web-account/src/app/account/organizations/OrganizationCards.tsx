"use client";

import { useCallback, useMemo, useState, type ReactNode } from "react";
import {
  Badge,
  Button,
  BuildingIcon,
  EmptyState,
  NodeTreeIllustration,
  PlusIcon,
  UsersIcon,
  useToast,
} from "@authn/ui";
import { useAuth } from "@authn/react";
import type { AuthnOrg, AuthnOrgMember } from "@authn/js";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HelpText } from "@/components/HelpText";
import { InfoHint } from "@/components/InfoHint";
import { LoadError, RowSkeleton } from "@/components/CardState";
import { SettingsCard, SettingsRow } from "@/components/SettingsCard";
import { useOrganizations } from "@/components/OrganizationsProvider";
import { formatDate } from "@/lib/datetime";
import { useResource, type ResourceResult } from "@/lib/useResource";
import { InvitationsCard } from "./InvitationsCard";
import { MembersDialog } from "./MembersDialog";
import { OrgFormDialog } from "./OrgFormDialog";

/**
 * Authn Platform — Organizations page body
 * File: apps/web-account/src/app/account/organizations/OrganizationCards.tsx
 *
 * One card per workspace, plus the invitations addressed to the reader.
 *
 * The list itself is not read here — it comes from the provider around the account
 * segment, shared with the sidebar so a workspace cannot appear in one and not the
 * other. What this file adds is the rosters: `GET .../members` for each workspace,
 * fetched as one keyed map rather than per card.
 *
 * The map is owned at this level because two things need the same rows. The card
 * shows a count and the reader's own role; the dialog behind "Manage" shows the
 * roster itself. Two owners would give a count that disagreed with the list it
 * opened — remove somebody in the dialog and the number behind it would still
 * include them.
 */

/** One roster per organization; `null` where the read failed, see {@link useRosters}. */
type RosterMap = Record<string, AuthnOrgMember[] | null>;

/** One dialog at a time, carrying the workspace it acts on. */
type Modal =
  | null
  | { kind: "members"; org: AuthnOrg }
  | { kind: "rename"; org: AuthnOrg }
  | { kind: "leave"; org: AuthnOrg }
  | { kind: "delete"; org: AuthnOrg };

/**
 * The header's create button.
 *
 * Exported separately because the page is server-rendered and this is the one part
 * of the header that is not: it opens a dialog. It reaches the same provider as the
 * cards below, so a workspace created here appears in both without either knowing
 * about the other.
 */
export function CreateOrganizationButton(): ReactNode {
  const { client } = useAuth();
  const toast = useToast();
  const { refetch } = useOrganizations();
  const [isOpen, setIsOpen] = useState(false);

  const create = useCallback(
    async ({ name, slug }: { name: string; slug: string }) => {
      // Omitted rather than sent empty: the engine derives a slug from the name when
      // the key is absent, and an empty string is a value that fails validation.
      const result = await client.createOrganization(slug === "" ? { name } : { name, slug });
      if (!result.ok) return result.error;

      setIsOpen(false);
      await refetch();
      toast.success(
        `${result.org.name} is ready`,
        "You are its first administrator. Invite the people who need access from its card below.",
      );
      return null;
    },
    [client, refetch, toast],
  );

  return (
    <>
      <Button
        variant="primary"
        leftIcon={<PlusIcon size={14} />}
        onClick={() => setIsOpen(true)}
      >
        New organization
      </Button>
      <OrgFormDialog
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        mode="create"
        onSubmit={create}
      />
    </>
  );
}

export function OrganizationCards(): ReactNode {
  const { client, user } = useAuth();
  const toast = useToast();
  const orgs = useOrganizations();
  const rosters = useRosters(orgs.organizations);

  const [modal, setModal] = useState<Modal>(null);
  const close = useCallback(() => setModal(null), []);

  /**
   * Refreshes the list and the rosters together.
   *
   * Called after every change that could alter either. Leaving a workspace removes a
   * card, and removing somebody else changes a count on one — and since the rosters
   * are keyed on the list, a list that changed without its rosters following would
   * leave a card reading a roster for a workspace that is gone.
   */
  const reload = useCallback(async () => {
    await orgs.refetch();
    await rosters.refetch();
  }, [orgs, rosters]);

  const leave = useCallback(
    async (org: AuthnOrg) => {
      const result = await client.removeOrgMember(org.id, user?.id ?? "");
      if (!result.ok) return result.error;

      close();
      void reload();
      toast.success(
        `You have left ${org.name}`,
        "Your account and everything in it is unaffected. Getting back in needs a new invitation.",
      );
      return null;
    },
    [client, close, reload, toast, user?.id],
  );

  const remove = useCallback(
    async (org: AuthnOrg) => {
      const result = await client.deleteOrganization(org.id);
      if (!result.ok) return result.error;

      close();
      void reload();
      toast.success(
        `${org.name} has been deleted`,
        "Its members have lost access to it. Their own accounts are untouched.",
      );
      return null;
    },
    [client, close, reload, toast],
  );

  const rename = useCallback(
    async (org: AuthnOrg, values: { name: string; slug: string }) => {
      const result = await client.updateOrganization(org.id, {
        name: values.name,
        // Sent unconditionally, including unchanged: the engine compares it against
        // the stored slug before checking uniqueness, so a workspace is never told
        // its own address is taken.
        slug: values.slug === "" ? org.slug : values.slug,
      });
      if (!result.ok) return result.error;

      close();
      void orgs.refetch();
      toast.success(
        `Renamed to ${result.org.name}`,
        values.slug !== "" && values.slug !== org.slug
          ? `Links using the old address, ${org.slug}, will no longer resolve.`
          : undefined,
      );
      return null;
    },
    [client, close, orgs, toast],
  );

  if (orgs.isLoading) {
    return (
      <Body>
        <SettingsCard title="Your organizations">
          <RowSkeleton rows={2} hasIcon label="your organizations" />
        </SettingsCard>
      </Body>
    );
  }

  /**
   * A failed list is the whole page, so it replaces it rather than sitting above a
   * set of cards that cannot be drawn. The invitations card is held back too: an
   * account that cannot read its workspaces cannot act on an invitation into one.
   */
  if (orgs.error && orgs.organizations.length === 0) {
    return (
      <Body>
        <SettingsCard title="Your organizations">
          <LoadError
            label="your organizations"
            message={orgs.error.message}
            onRetry={() => void orgs.refetch()}
            isRetrying={orgs.isRefetching}
          />
        </SettingsCard>
      </Body>
    );
  }

  return (
    <Body>
      {orgs.organizations.length === 0 ? (
        <EmptyState
          illustration={<NodeTreeIllustration size={140} />}
          title="You are not in any organizations"
          description="Organizations are shared workspaces with their own members and roles. Create one, or accept an invitation to somebody else's below."
        />
      ) : (
        orgs.organizations.map((org) => (
          <OrgCard
            key={org.id}
            org={org}
            roster={rosters.data?.[org.id] ?? null}
            isRosterLoading={rosters.isLoading}
            viewerId={user?.id}
            onManage={() => setModal({ kind: "members", org })}
            onRename={() => setModal({ kind: "rename", org })}
            onLeave={() => setModal({ kind: "leave", org })}
            onDelete={() => setModal({ kind: "delete", org })}
          />
        ))
      )}

      <InvitationsCard onAccepted={reload} />

      <MembersDialog
        /* Remounted per workspace, so opening a second one cannot show the first
           one's outstanding invitations while its own request is in flight, and
           cannot carry over a half-typed invitation. */
        key={modal?.kind === "members" ? modal.org.id : "no-org"}
        isOpen={modal?.kind === "members"}
        onClose={close}
        org={modal?.kind === "members" ? modal.org : null}
        roster={modal?.kind === "members" ? (rosters.data?.[modal.org.id] ?? null) : null}
        isRosterLoading={rosters.isLoading}
        viewerId={user?.id}
        onRosterChanged={reload}
      />

      <OrgFormDialog
        isOpen={modal?.kind === "rename"}
        onClose={close}
        mode="rename"
        initialName={modal?.kind === "rename" ? modal.org.name : ""}
        initialSlug={modal?.kind === "rename" ? modal.org.slug : ""}
        onSubmit={(values) =>
          modal?.kind === "rename" ? rename(modal.org, values) : Promise.resolve(null)
        }
      />

      <ConfirmDialog
        isOpen={modal?.kind === "leave"}
        onClose={close}
        title="Leave this organization?"
        description={
          modal?.kind === "leave"
            ? `You lose access to ${modal.org.name} straight away. Getting back in needs somebody there to invite you again.`
            : undefined
        }
        confirmLabel="Leave it"
        cancelLabel="Stay a member"
        subject="this membership"
        onConfirm={() => (modal?.kind === "leave" ? leave(modal.org) : Promise.resolve(null))}
      >
        Your account, your sign-in methods and your other workspaces are unaffected.
        {modal?.kind === "leave" && modal.org.isAdmin
          ? " You administer this one, so if you are its only administrator you will be asked to promote somebody else first."
          : null}
      </ConfirmDialog>

      <ConfirmDialog
        isOpen={modal?.kind === "delete"}
        onClose={close}
        title="Delete this organization?"
        description={
          modal?.kind === "delete"
            ? `${modal.org.name}, its members and its outstanding invitations are removed. This cannot be undone.`
            : undefined
        }
        consequence="Everyone in this workspace loses access to it immediately, without being told."
        confirmLabel="Delete it"
        cancelLabel="Keep it"
        subject="this organization"
        onConfirm={() => (modal?.kind === "delete" ? remove(modal.org) : Promise.resolve(null))}
      >
        Nobody&rsquo;s account is deleted — each member keeps their own, and everything in
        it.
      </ConfirmDialog>
    </Body>
  );
}

/** The page's column. Declared once so the four returns above cannot disagree on it. */
function Body({ children }: { children: ReactNode }): ReactNode {
  return (
    <div className="mx-auto flex w-full max-w-page flex-col gap-xl px-lg py-xxl sm:px-xl">
      {children}
    </div>
  );
}

interface OrgCardProps {
  org: AuthnOrg;
  /** This workspace's roster, or null while it loads and if the read failed. */
  roster: AuthnOrgMember[] | null;
  isRosterLoading: boolean;
  viewerId: string | undefined;
  onManage: () => void;
  onRename: () => void;
  onLeave: () => void;
  onDelete: () => void;
}

function OrgCard({
  org,
  roster,
  isRosterLoading,
  viewerId,
  onManage,
  onRename,
  onLeave,
  onDelete,
}: OrgCardProps): ReactNode {
  /**
   * The reader's own row, for the role name.
   *
   * `org.isAdmin` already says whether they may administer it, but not what their
   * role is called — and a workspace can name its roles whatever it likes, so
   * "Organization Admin" and "Owner" are both possible answers to the same
   * question. The badge shows the tier and the text beside it shows the name.
   */
  const mine = roster?.find((member) => member.userId === viewerId) ?? null;

  const memberCount = roster?.length ?? null;
  const adminCount = roster?.filter((member) => member.isAdmin === true).length ?? null;

  return (
    <SettingsCard
      id={org.slug}
      title={org.name}
      description={`Created ${formatDate(org.createdAt)}.`}
      action={<InfoHint topic="organizations" label="organizations" position="left" />}
      footer={
        <>
          {/* Left of the buttons and allowed to grow, so the explanation and the
              actions share one row on a wide screen and stack on a narrow one. */}
          <HelpText topic="organizations" short className="mr-auto text-caption text-ash" />
          <Button variant="secondary" onClick={onLeave}>
            Leave
          </Button>
          {org.isAdmin ? (
            <Button variant="destructive" onClick={onDelete}>
              Delete organization
            </Button>
          ) : null}
        </>
      }
    >
      <SettingsRow
        icon={UsersIcon}
        accent="blue"
        label="Members"
        value={
          isRosterLoading ? (
            <span className="text-body-sm text-ash">Counting…</span>
          ) : memberCount === null ? (
            <span className="text-body-sm text-ash">Not available</span>
          ) : (
            <span className="flex flex-wrap items-center gap-sm">
              <span className="text-body-sm text-ink">
                {memberCount === 1 ? "1 person" : `${memberCount} people`}
              </span>
              <Badge variant={org.isAdmin ? "green" : "gray"} size="sm">
                {mine?.roleName ?? (org.isAdmin ? "Administrator" : "Member")}
              </Badge>
            </span>
          )
        }
        hint={describeRoster(org.isAdmin, memberCount, adminCount)}
        action={
          <Button variant="secondary" onClick={onManage}>
            {org.isAdmin ? "Manage members" : "View members"}
          </Button>
        }
      />

      <SettingsRow
        icon={BuildingIcon}
        accent="blue"
        label="Address"
        value={<span className="font-mono text-body-sm text-ink">{org.slug}</span>}
        hint="Identifies this workspace in links and in API calls. Changing it stops the old one resolving."
        action={
          org.isAdmin ? (
            <Button variant="secondary" onClick={onRename}>
              Rename
            </Button>
          ) : undefined
        }
      />
    </SettingsCard>
  );
}

/**
 * The line under the member count.
 *
 * Says something different to an administrator than to a member, because the useful
 * fact differs: an administrator needs to know whether they are the only one, since
 * that is what will stop them leaving. A member does not, and telling them how many
 * administrators a workspace has is somebody else's business.
 */
function describeRoster(
  isAdmin: boolean,
  memberCount: number | null,
  adminCount: number | null,
): string | undefined {
  if (memberCount === null) return "The roster could not be read. Open it to try again.";
  if (!isAdmin) return "You can see who else is here, but not invite or remove anyone.";
  if (adminCount === 1) {
    return "You are the only administrator, so you cannot leave until somebody else is one.";
  }
  if (adminCount !== null && adminCount > 1) {
    return `${adminCount} of them can administer this workspace, including you.`;
  }
  return undefined;
}

/**
 * Every workspace's roster, as one keyed map.
 *
 * Keyed on the joined ids rather than the array, so the loader keeps its identity
 * across a re-render that hands back an equal-but-new list — `useResource` refetches
 * whenever the loader changes, and a loader rebuilt on every render would fetch
 * forever.
 *
 * Never resolves to a failure. One workspace answering 403 or 404 must not blank the
 * others, so a failed read is `null` under its own key and the card for it says the
 * roster is unavailable while the rest of the page stands.
 */
function useRosters(organizations: AuthnOrg[]) {
  const { client, isAuthenticated } = useAuth();
  const key = useMemo(() => organizations.map((org) => org.id).join(","), [organizations]);

  const load = useCallback(async (): Promise<ResourceResult<RosterMap>> => {
    const ids = key === "" ? [] : key.split(",");
    const entries = await Promise.all(
      ids.map(async (id) => {
        const result = await client.listOrgMembers(id);
        return [id, result.ok ? result.members : null] as const;
      }),
    );
    return { ok: true, data: Object.fromEntries(entries) };
  }, [client, key]);

  return useResource(load, { enabled: isAuthenticated });
}
