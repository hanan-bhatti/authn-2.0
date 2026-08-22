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

/**
 * TwoFactorMethod names a second factor a pending login may be completed with.
 *
 * `backup_code` is the engine's name for a recovery code. It never appears
 * alone: a recovery code is a way past a factor the account holds rather than a
 * factor in its own right, so the engine offers it only alongside another entry.
 */
export type TwoFactorMethod = "totp" | "passkey" | "sms" | "backup_code";

/**
 * AuthResult is what every credential-presenting call answers with.
 *
 * A password can succeed without signing anyone in. When the account holds a
 * second factor the engine answers 200 with a challenge instead of a session, so
 * "not an error" and "authenticated" are separate questions and the type asks
 * them separately: `ok` distinguishes a refusal from a reply, and `mfaRequired`
 * distinguishes a session from a challenge. Narrow on both.
 *
 * @example
 * ```ts
 * const result = await authn.login({ email, password });
 * if (!result.ok) return showError(result.error);
 * if (result.mfaRequired) return showChallenge(result.mfaToken, result.methods);
 * // result.session is a real session only here.
 * ```
 */
export type AuthResult =
  | {
      ok: true;
      session: AuthnSession;
      mfaRequired?: false;
      mfaToken?: undefined;
      methods?: undefined;
      policyWarning?: PolicyWarning;
    }
  | {
      ok: true;
      /**
       * Absent by construction: nothing has been authenticated yet. The client
       * stores no session and reports no authenticated user until the second
       * factor is verified.
       */
      session?: undefined;
      mfaRequired: true;
      /**
       * Short-lived proof that the first factor was accepted. Every 2FA
       * verification call takes it; it is not an access token and authorises
       * nothing else.
       */
      mfaToken: string;
      /**
       * What this account can be challenged with, most recently used first, so a
       * UI can open on the factor its owner reached for last time. Never empty.
       */
      methods: TwoFactorMethod[];
      /**
       * Who is signing in, for addressing the challenge screen. Carried here
       * because there is no session to read it from yet.
       */
      user: AuthnUser;
      policyWarning?: undefined;
    }
  | { ok: false; error: AuthnError };

export type SessionResult =
  | { ok: true; session: AuthnSession }
  | { ok: false; error: AuthnError };

export type VoidResult =
  | { ok: true; message?: string; count?: number }
  | { ok: false; error: AuthnError };
