/**
 * @authn/js — Common User & Session Types
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

export interface AuthnUser {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  status: "active" | "suspended" | "banned";
  createdAt: string;
}

export interface AuthnSession {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  user: AuthnUser;
}

export interface PolicyWarning {
  requiresPasswordUpgrade?: boolean;
  requiresEmailVerification?: boolean;
  missingCriteria?: string[];
}

export type AuthResult =
  | {
      ok: true;
      session: AuthnSession;
      mfaRequired?: boolean;
      mfaToken?: string;
      policyWarning?: PolicyWarning;
    }
  | { ok: false; error: AuthnError };

export type SessionResult =
  | { ok: true; session: AuthnSession }
  | { ok: false; error: AuthnError };

export type VoidResult =
  | { ok: true; message?: string; count?: number }
  | { ok: false; error: AuthnError };
