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
  createdAt: string;
}

export interface AuthnOrgMember {
  id: string;
  organizationId: string;
  userId: string;
  roleId: string;
  role?: string;
  email?: string;
  name?: string;
  assignedByUserId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthnOrgInvitation {
  id: string;
  organizationId: string;
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
