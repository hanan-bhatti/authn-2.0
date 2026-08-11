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

export type RecoveryEmailResult =
  | { ok: true; recoveryEmail: AuthnRecoveryEmail | null; recoveryEmailVerified?: boolean }
  | { ok: false; error: AuthnError };

export type SocialAccountsResult =
  | { ok: true; accounts: AuthnSocialAccount[] }
  | { ok: false; error: AuthnError };
