/**
 * @authn/js — Organization Types
 *
 * Request params, result types, and entity shapes for the B2B Organizations group.
 * Routes: /v1/client/organizations/*
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

// ─── Entity Shapes ──────────────────────────────────────────────────────────

export interface AuthnOrg {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  logoUrl?: string;
  metadata?: Record<string, unknown>;
  /**
   * Whether *the reader* may administer this organization — rename it, invite to
   * it, remove members, delete it. Per-caller rather than a property of the
   * organization, so two members listing the same workspace get different values.
   *
   * It is the same answer the mutating endpoints will give, which is what makes it
   * safe to hide a control on: a UI that renders the button anyway gets a 403 the
   * user cannot act on.
   */
  isAdmin: boolean;
  createdAt: string;
}

export interface AuthnOrgMember {
  id: string;
  organizationId: string;
  userId: string;
  roleId: string;
  /**
   * The role's stable identifier — `org_admin` for an administrator. Branch on
   * this rather than on {@link roleName}, which is display text and translatable.
   */
  roleSlug?: string;
  /** The role's display name, for showing beside the member. */
  roleName?: string;
  /**
   * Whether this member's role carries organization-admin rights, derived by the
   * engine from the same predicate its authorization checks use.
   *
   * Distinct from {@link AuthnOrg.isAdmin}: that one describes the reader, this
   * one describes the row.
   */
  isAdmin?: boolean;
  /**
   * The member's display name, address, handle and picture, as far as they have
   * set them.
   *
   * They travel with the membership because no client route resolves a user ID:
   * `GET /v1/client/user/profile` answers for the reader only. Without them a
   * roster is a list of opaque identifiers, and the reader cannot pick out their
   * own row in it.
   *
   * Every member of an organization may read its roster, so these are visible to
   * all of them rather than to administrators alone.
   */
  email?: string;
  name?: string;
  username?: string;
  avatarUrl?: string;
  assignedByUserId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthnOrgInvitation {
  id: string;
  organizationId: string;
  /**
   * The display name of the organization being joined.
   *
   * It travels with the invitation because a recipient has no other way to name
   * what they are being asked to join: they are not a member yet, so the endpoint
   * that would resolve the ID answers 403 for them.
   */
  organizationName?: string;
  email: string;
  roleId: string;
  invitedByUserId?: string;
  /** Only present for the caller who created the invitation — never in listings. */
  invitationToken?: string;
  status: "pending" | "accepted" | "expired" | string;
  expiresAt: string;
  createdAt: string;
}

// ─── Request Param Types ─────────────────────────────────────────────────────

export interface CreateOrgParams {
  name: string;
  slug?: string;
  logoUrl?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateOrgParams {
  name?: string;
  slug?: string;
  logoUrl?: string;
  metadata?: Record<string, unknown>;
}

export interface InviteOrgMemberParams {
  email: string;
  roleId?: string;
  role?: string;
  expiresHrs?: number;
}

export interface AcceptOrgInvitationParams {
  invitationToken: string;
}

export interface UpdateOrgMemberRoleParams {
  roleId: string;
}

// ─── Result Types ────────────────────────────────────────────────────────────

export type CreateOrgResult =
  | { ok: true; org: AuthnOrg }
  | { ok: false; error: AuthnError };

export type GetOrgResult =
  | { ok: true; org: AuthnOrg }
  | { ok: false; error: AuthnError };

export type ListOrgsResult =
  | { ok: true; organizations: AuthnOrg[]; total: number }
  | { ok: false; error: AuthnError };

export type UpdateOrgResult =
  | { ok: true; org: AuthnOrg }
  | { ok: false; error: AuthnError };

export type DeleteOrgResult =
  | { ok: true; orgId: string; message: string }
  | { ok: false; error: AuthnError };

export type InviteOrgMemberResult =
  | { ok: true; invitation: AuthnOrgInvitation }
  | { ok: false; error: AuthnError };

export type AcceptOrgInvitationResult =
  | { ok: true; member: AuthnOrgMember; message: string }
  | { ok: false; error: AuthnError };

export type ListOrgMembersResult =
  | { ok: true; members: AuthnOrgMember[]; total: number }
  | { ok: false; error: AuthnError };

export type UpdateOrgMemberRoleResult =
  | { ok: true; member: AuthnOrgMember }
  | { ok: false; error: AuthnError };

/**
 * RemoveOrgMemberResult is the answer to both removing someone and leaving.
 *
 * `left` distinguishes them. The engine sets it when the removed member was the
 * caller, which is the case a UI has to treat differently: the workspace it was
 * showing is no longer readable, so it navigates away instead of refreshing a list
 * that will now answer 403.
 */
export type RemoveOrgMemberResult =
  | { ok: true; message: string; left: boolean }
  | { ok: false; error: AuthnError };

export type ListInvitationsResult =
  | { ok: true; invitations: AuthnOrgInvitation[]; total: number }
  | { ok: false; error: AuthnError };

/**
 * ListOrgInvitationsResult is the outstanding invitations *into* one organization.
 *
 * The mirror image of {@link ListInvitationsResult}, which is the invitations
 * addressed *to* the reader. This one is readable only by an administrator of the
 * organization, and every entry carries somebody's email address — so it belongs
 * beside the control that can withdraw them rather than on general display.
 *
 * `invitationToken` is absent on every entry. Only the caller who created an
 * invitation ever sees its token, so an administrator cannot recover a link a
 * recipient has lost; withdraw it and send another.
 */
export type ListOrgInvitationsResult =
  | { ok: true; invitations: AuthnOrgInvitation[]; total: number }
  | { ok: false; error: AuthnError };

export type RevokeOrgInvitationResult =
  | { ok: true; invitationId: string; message: string }
  | { ok: false; error: AuthnError };
