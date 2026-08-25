/**
 * @authn/js — User Profile & Accounts Types
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";
import type { AuthnUser } from "./common";

export interface AuthnProfile extends AuthnUser {
  givenName?: string;
  familyName?: string;
  avatarUrl?: string;
  phone?: string;
  phoneNumber?: string;
  phoneVerified?: boolean;
  tenantId?: string;
  recoveryEmail?: string;
  recoveryEmailVerified?: boolean;
  locale?: string;
  metadata?: Record<string, unknown>;
  updatedAt?: string;
}

export interface AuthnSocialAccount {
  id?: string;
  provider: "google" | "github" | "apple" | "microsoft" | string;
  providerUserId?: string;
  email?: string;
  linkedAt?: string;
  connectedAt?: string;
}

export interface AuthnRecoveryEmailObject {
  email: string;
  verified?: boolean;
  setAt?: string;
}

export type AuthnRecoveryEmail = AuthnRecoveryEmailObject | string;

export interface UpdateProfileParams {
  name?: string;
  /**
   * Replaces the handle. Pass an empty string to release it and go back to having
   * none — omitting the key leaves it alone, since a partial update cannot tell
   * "unset" from "clear".
   *
   * Rejected with `already_exists` when another account in the same tenant holds
   * it, and with `validation_failed` when it breaks a naming rule, in which case
   * the error message names the rule. Call `checkUsername` first if you want to
   * tell the user before they submit.
   */
  username?: string;
  givenName?: string;
  familyName?: string;
  avatarUrl?: string;
  phone?: string;
  locale?: string;
  metadata?: Record<string, unknown>;
}

export type ProfileResult =
  | { ok: true; profile: AuthnProfile }
  | { ok: false; error: AuthnError };

/**
 * DeleteAccountParams re-authenticates the caller before the account is destroyed.
 *
 * A session cookie alone is not proof enough: it may be one someone else walked up
 * to. Send `password` for any account that holds one. An account created through a
 * social provider, a passkey or a magic link has none to re-enter, so it is checked
 * on `totpCode` instead — the engine answers 401 `totp_required` when that is the
 * factor it wants and nothing was sent.
 */
export interface DeleteAccountParams {
  password?: string;
  totpCode?: string;
}

/**
 * BlockingOrganization is one workspace standing in the way of a deletion.
 *
 * Returned under `error.details.organizations` on the 409, so the refusal can name
 * each workspace and link to it rather than telling the reader to go and look.
 */
export interface BlockingOrganization {
  id: string;
  name: string;
  slug: string;
  /**
   * How many members other than the caller are in it. Always at least one on a
   * blocking entry: a workspace where the caller is alone is deleted alongside the
   * account, there being nobody left to strand.
   */
  other_members: number;
}

export type RecoveryEmailResult =
  | { ok: true; recoveryEmail: AuthnRecoveryEmail | null; recoveryEmailVerified?: boolean }
  | { ok: false; error: AuthnError };

export type SocialAccountsResult =
  | { ok: true; accounts: AuthnSocialAccount[] }
  | { ok: false; error: AuthnError };
