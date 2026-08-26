"use client";

import { useCallback, useState, type ReactNode } from "react";
import {
  Avatar,
  Badge,
  Button,
  CopyButton,
  Dialog,
  FormField,
  Input,
  InfoIcon,
  MailIcon,
  Select,
  useToast,
} from "@authn/ui";
import { useAuth } from "@authn/react";
import type { AuthnOrg, AuthnOrgInvitation, AuthnOrgMember } from "@authn/js";
import { LoadError, RowSkeleton } from "@/components/CardState";
import { presentSaveError } from "@/lib/authError";
import { formatUntil } from "@/lib/datetime";
import { useResource, type ResourceResult } from "@/lib/useResource";

/**
 * Authn Platform — Members of one organization
 * File: apps/web-account/src/app/account/organizations/MembersDialog.tsx
 *
 * Who is in a workspace, and for an administrator the three things they can do
 * about it: invite somebody, change what a member may do, and take them out.
 *
 * The roster arrives as a prop rather than being read here. The card behind this
 * dialog shows a count from the same rows, and a dialog that fetched its own would
 * let the two disagree — remove somebody and the number behind the dialog would
 * still include them. Mutations call `onRosterChanged`, which reloads the page's
 * copy, and this list follows.
 *
 * Outstanding invitations *are* read here, because nothing outside this dialog
 * shows them and only an administrator may. They are the other half of the roster:
 * a workspace with two members and four invitations out is not a workspace with two
 * members, and an administrator wondering why somebody has not appeared needs to
 * see that their invitation is still sitting there.
 */

/** The two roles this dialog can assign, by slug. */
const ROLE_OPTIONS = [
  { value: "org_member", label: "Member — can see the workspace and who is in it" },
  { value: "org_admin", label: "Administrator — can also invite, remove and rename" },
];

export interface MembersDialogProps {
  isOpen: boolean;
  onClose: () => void;
  /** Null while no workspace is selected, which is every render but one. */
  org: AuthnOrg | null;
  roster: AuthnOrgMember[] | null;
  isRosterLoading: boolean;
  viewerId: string | undefined;
  /** Reloads the page's organization list and rosters after a change here. */
  onRosterChanged: () => Promise<void>;
}

export function MembersDialog({
  isOpen,
  onClose,
  org,
  roster,
  isRosterLoading,
  viewerId,
  onRosterChanged,
}: MembersDialogProps): ReactNode {
  const { client, isAuthenticated } = useAuth();
  const toast = useToast();

  const orgId = org?.id ?? "";
  const canAdminister = org?.isAdmin === true;

  /**
   * The invitations into this workspace that nobody has redeemed yet.
   *
   * Held back for a plain member: the endpoint requires org-admin rights, so asking
   * would answer 403 and render as a failure on a dialog that is working correctly.
   */
  const loadInvites = useCallback(async (): Promise<ResourceResult<AuthnOrgInvitation[]>> => {
    const result = await client.listOrgInvitations(orgId);
    return result.ok ? { ok: true, data: result.invitations } : { ok: false, error: result.error };
  }, [client, orgId]);

  const invites = useResource(loadInvites, {
    enabled: isAuthenticated && isOpen && canAdminister && orgId !== "",
  });

  const [email, setEmail] = useState("");
  const [roleSlug, setRoleSlug] = useState("org_member");
  const [inviteMessage, setInviteMessage] = useState<string | null>(null);
  const [isInviting, setIsInviting] = useState(false);

  /**
   * The invitation just created, kept on screen for as long as the dialog is open.
   *
   * It has to be: the engine does not send the email itself — that is a webhook
   * subscriber's job — and the redemption token is returned to whoever created the
   * invitation and to nobody else, ever again. Dropping it after a toast would leave
   * an administrator with an invitation they cannot deliver.
   */
  const [issued, setIssued] = useState<AuthnOrgInvitation | null>(null);

  /** The member whose removal is waiting for a second click. */
  const [pendingRemoval, setPendingRemoval] = useState<string | null>(null);
  const [rowMessage, setRowMessage] = useState<string | null>(null);
  const [busyMember, setBusyMember] = useState<string | null>(null);

  const invite = useCallback(async () => {
    const address = email.trim().toLowerCase();
    if (address === "") {
      setInviteMessage("Enter the email address to invite.");
      return;
    }

    setIsInviting(true);
    setInviteMessage(null);
    const result = await client.inviteOrgMember(orgId, { email: address, roleId: roleSlug });
    setIsInviting(false);

    if (!result.ok) {
      setInviteMessage(presentSaveError(result.error, "invitation"));
      return;
    }

    setIssued(result.invitation);
    setEmail("");
    void invites.refetch();
  }, [client, email, invites, orgId, roleSlug]);

  const changeRole = useCallback(
    async (member: AuthnOrgMember) => {
      const next = member.isAdmin === true ? "org_member" : "org_admin";
      setBusyMember(member.userId);
      setRowMessage(null);
      const result = await client.updateOrgMemberRole(orgId, member.userId, { roleId: next });
      setBusyMember(null);

      if (!result.ok) {
        setRowMessage(presentSaveError(result.error, "member's role"));
        return;
      }

      await onRosterChanged();
      toast.success(
        next === "org_admin"
          ? `${describe(member)} can now administer this workspace`
          : `${describe(member)} is now an ordinary member`,
        next === "org_admin"
          ? "They can invite people, change roles and remove members, including you."
          : "They keep access to the workspace and can no longer change who is in it.",
      );
    },
    [client, onRosterChanged, orgId, toast],
  );

  const removeMember = useCallback(
    async (member: AuthnOrgMember) => {
      setBusyMember(member.userId);
      setRowMessage(null);
      const result = await client.removeOrgMember(orgId, member.userId);
      setBusyMember(null);

      if (!result.ok) {
        setRowMessage(presentSaveError(result.error, "membership"));
        return;
      }

      setPendingRemoval(null);
      await onRosterChanged();
      toast.success(
        `${describe(member)} has been removed`,
        "They lose access to this workspace at once. Their own account is untouched.",
      );
    },
    [client, onRosterChanged, orgId, toast],
  );

  const revokeInvite = useCallback(
    async (invitation: AuthnOrgInvitation) => {
      const result = await client.revokeOrgInvitation(orgId, invitation.id);
      if (!result.ok) {
        setRowMessage(presentSaveError(result.error, "invitation"));
        return;
      }

      void invites.refetch();
      // Cleared when it is the one being withdrawn, so the panel offering a code
      // that no longer works goes away with it.
      setIssued((current) => (current?.id === invitation.id ? null : current));
      toast.success(
        "Invitation withdrawn",
        `The link sent to ${invitation.email} no longer works. Invite them again to send a new one.`,
      );
    },
    [client, invites, orgId, toast],
  );

  if (!org) return null;

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={org.name}
      description={
        canAdminister
          ? "Everyone in this workspace, and the invitations still outstanding."
          : "Everyone in this workspace. Inviting and removing people needs organization-admin rights."
      }
      maxWidth="lg"
    >
      <div className="flex flex-col gap-lg">
        <section className="flex flex-col gap-sm">
          <h3 className="text-caption tracking-wide text-mute uppercase">Members</h3>

          <div className="overflow-hidden rounded-md border border-hairline">
            {isRosterLoading ? (
              <RowSkeleton rows={2} hasIcon label="the members of this workspace" />
            ) : roster === null ? (
              <LoadError
                label="the members of this workspace"
                onRetry={() => void onRosterChanged()}
              />
            ) : (
              roster.map((member) => (
                <MemberRow
                  key={member.id}
                  member={member}
                  isSelf={member.userId === viewerId}
                  canAdminister={canAdminister}
                  isBusy={busyMember === member.userId}
                  isConfirmingRemoval={pendingRemoval === member.userId}
                  onAskRemoval={() => {
                    setRowMessage(null);
                    setPendingRemoval(member.userId);
                  }}
                  onCancelRemoval={() => setPendingRemoval(null)}
                  onConfirmRemoval={() => void removeMember(member)}
                  onChangeRole={() => void changeRole(member)}
                />
              ))
            )}
          </div>

          {rowMessage ? <p className="text-body-sm text-accent-red">{rowMessage}</p> : null}
        </section>

        {canAdminister ? (
          <>
            <section className="flex flex-col gap-sm">
              <h3 className="text-caption tracking-wide text-mute uppercase">
                Invite somebody
              </h3>

              <form
                noValidate
                className="flex flex-col gap-md rounded-md border border-hairline p-md"
                onSubmit={(event) => {
                  event.preventDefault();
                  void invite();
                }}
              >
                <FormField label="Email address" isRequired>
                  <Input
                    type="email"
                    value={email}
                    placeholder="colleague@example.com"
                    autoComplete="off"
                    disabled={isInviting}
                    leftIcon={<MailIcon size={14} />}
                    onChange={(event) => {
                      setEmail(event.target.value);
                      setInviteMessage(null);
                    }}
                  />
                </FormField>

                <FormField
                  label="Role on joining"
                  hint="Changeable afterwards from the list above."
                >
                  <Select
                    options={ROLE_OPTIONS}
                    value={roleSlug}
                    disabled={isInviting}
                    onChange={(event) => setRoleSlug(event.target.value)}
                  />
                </FormField>

                {inviteMessage ? (
                  <p className="text-body-sm text-accent-red">{inviteMessage}</p>
                ) : null}

                <div className="flex justify-end">
                  <Button type="submit" variant="primary" isLoading={isInviting}>
                    Create invitation
                  </Button>
                </div>
              </form>
            </section>

            {issued ? <IssuedInvitation invitation={issued} /> : null}

            <section className="flex flex-col gap-sm">
              <h3 className="text-caption tracking-wide text-mute uppercase">
                Waiting to be accepted
              </h3>

              <div className="overflow-hidden rounded-md border border-hairline">
                {invites.isLoading ? (
                  <RowSkeleton rows={1} label="outstanding invitations" />
                ) : !invites.data ? (
                  <LoadError
                    label="outstanding invitations"
                    message={invites.error?.message}
                    onRetry={() => void invites.refetch()}
                    isRetrying={invites.isRefetching}
                  />
                ) : invites.data.length === 0 ? (
                  <p className="p-md text-body-sm text-ash">
                    No invitations are outstanding. Everyone invited has either joined or had
                    their invitation withdrawn.
                  </p>
                ) : (
                  invites.data.map((invitation) => (
                    <div
                      key={invitation.id}
                      className="flex flex-wrap items-center justify-between gap-md p-md not-first:border-t not-first:border-hairline"
                    >
                      <div className="flex min-w-0 flex-1 basis-[14rem] flex-col gap-xxs">
                        <span className="truncate text-body-sm text-ink">{invitation.email}</span>
                        <span className="text-caption text-ash">
                          {invitation.status === "pending"
                            ? `Expires ${formatUntil(invitation.expiresAt)}`
                            : invitation.status}
                        </span>
                      </div>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => void revokeInvite(invitation)}
                      >
                        Withdraw
                      </Button>
                    </div>
                  ))
                )}
              </div>
            </section>
          </>
        ) : null}

        <div className="flex justify-end">
          <Button variant="ghost" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

interface MemberRowProps {
  member: AuthnOrgMember;
  isSelf: boolean;
  canAdminister: boolean;
  isBusy: boolean;
  isConfirmingRemoval: boolean;
  onAskRemoval: () => void;
  onCancelRemoval: () => void;
  onConfirmRemoval: () => void;
  onChangeRole: () => void;
}

/**
 * One person in the workspace.
 *
 * The reader's own row carries no controls. Leaving is on the card behind this
 * dialog, which knows to refresh the page afterwards — a "remove" here that
 * happened to be aimed at yourself would succeed and leave the dialog open on a
 * workspace it can no longer read.
 */
function MemberRow({
  member,
  isSelf,
  canAdminister,
  isBusy,
  isConfirmingRemoval,
  onAskRemoval,
  onCancelRemoval,
  onConfirmRemoval,
  onChangeRole,
}: MemberRowProps): ReactNode {
  const label = describe(member);
  /**
   * The line under the name, and never a repeat of it.
   *
   * The address when the name is what is on top, the handle when the address is,
   * and the role name when the account has nothing else to show — a row reading
   * "colleague@example.com" twice looks like a rendering fault.
   */
  const secondary =
    member.name && member.email
      ? member.email
      : member.username && member.username !== label
        ? `@${member.username}`
        : (member.roleName ?? null);

  return (
    <div className="flex flex-wrap items-center justify-between gap-md p-md not-first:border-t not-first:border-hairline">
      <div className="flex min-w-0 flex-1 basis-[14rem] items-center gap-sm">
        <Avatar size="sm" name={label} src={member.avatarUrl} />
        <div className="flex min-w-0 flex-col">
          <span className="flex items-center gap-xs truncate text-body-sm text-ink">
            {label}
            {isSelf ? (
              <Badge variant="orange" size="sm">
                you
              </Badge>
            ) : null}
          </span>
          {secondary ? (
            <span className="truncate text-caption text-ash">{secondary}</span>
          ) : null}
        </div>
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-sm">
        <Badge variant={member.isAdmin === true ? "green" : "gray"} size="sm">
          {member.roleName ?? (member.isAdmin === true ? "Administrator" : "Member")}
        </Badge>

        {canAdminister && !isSelf ? (
          isConfirmingRemoval ? (
            /* Confirmed in place rather than in a second dialog. A dialog opened over
               this one would be two fixed overlays with no stacking order between
               them, and the reader would be confirming against a backdrop that has
               dimmed the thing they are confirming about. */
            <>
              <span className="text-caption text-accent-red">Remove them?</span>
              <Button variant="ghost" size="sm" disabled={isBusy} onClick={onCancelRemoval}>
                No
              </Button>
              <Button
                variant="destructive"
                size="sm"
                isLoading={isBusy}
                onClick={onConfirmRemoval}
              >
                Yes, remove
              </Button>
            </>
          ) : (
            <>
              <Button variant="ghost" size="sm" disabled={isBusy} onClick={onChangeRole}>
                {member.isAdmin === true ? "Make member" : "Make admin"}
              </Button>
              <Button variant="destructive" size="sm" disabled={isBusy} onClick={onAskRemoval}>
                Remove
              </Button>
            </>
          )
        ) : null}
      </div>
    </div>
  );
}

/**
 * The invitation that has just been created, with its redemption code.
 *
 * Shown because the code is not recoverable. The engine returns it once, to the
 * caller that created the invitation, and withholds it from every listing — so this
 * panel is the only place it exists outside the database, and closing the dialog
 * without copying it means withdrawing the invitation and issuing another.
 */
function IssuedInvitation({ invitation }: { invitation: AuthnOrgInvitation }): ReactNode {
  const token = invitation.invitationToken ?? "";

  /**
   * Built from the browser's own origin, so a link copied on a staging host does not
   * send the recipient to production. The page it points at reads `invite` and fills
   * in the code for them.
   */
  const link =
    typeof window === "undefined"
      ? ""
      : `${window.location.origin}/account/organizations?invite=${encodeURIComponent(token)}`;

  return (
    <section className="flex flex-col gap-md rounded-md border border-accent-orange/40 bg-accent-orange/[0.06] p-md">
      <div className="flex items-start gap-sm">
        <InfoIcon variant="line" size={16} className="mt-px shrink-0 text-accent-orange" />
        <div className="flex flex-col gap-xxs">
          <p className="text-body-sm text-ink">
            Send this to {invitation.email} yourself.
          </p>
          <p className="text-caption text-charcoal">
            We do not email it for you, and the code cannot be read again — not by you and
            not by us. If it is lost, withdraw the invitation and create another. It expires{" "}
            {formatUntil(invitation.expiresAt)}.
          </p>
        </div>
      </div>

      {/* `break-all` and not `truncate`: a 64-character code that has been cut off is
          worse than useless, because it looks complete. */}
      <p className="rounded-md border border-hairline bg-canvas p-sm font-mono text-caption break-all text-ink">
        {token}
      </p>

      <div className="flex flex-wrap gap-sm">
        <CopyButton value={token} label="Copy code" />
        {link === "" ? null : <CopyButton value={link} label="Copy invitation link" />}
      </div>
    </section>
  );
}

/**
 * What to call a member: their name, else their handle, else their address.
 *
 * The handle comes before the address because it is what they chose to be called
 * by. The last resort is deliberately vague rather than the user ID — an
 * identifier in the place a name goes reads as a fault, and every row still
 * carries the role badge and the controls that act on it.
 */
function describe(member: AuthnOrgMember): string {
  if (member.name) return member.name;
  if (member.username) return `@${member.username}`;
  return member.email ?? "This member";
}
