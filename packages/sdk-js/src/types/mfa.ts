/**
 * @authn/js — 2FA & Multi-Factor Auth Types
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

export type EnrollTOTPResult =
  | {
      ok: true;
      secret: string;
      qrCodeUrl?: string;
      uri?: string;
    }
  | { ok: false; error: AuthnError };

export interface ConfirmTOTPParams {
  code: string;
}

export interface Confirm2FAData {
  message?: string;
  recoveryCodes?: string[];
  recoveryCodesCreated?: boolean;
}

export type Confirm2FAResult =
  | ({ ok: true } & Confirm2FAData)
  | { ok: false; error: AuthnError };

export interface DisableTOTPParams {
  password?: string;
}

export interface VerifyTOTPParams {
  code: string;
  mfaToken?: string;
  method?: string;
}

export type VerifyTOTPResult =
  | { ok: true; session?: import("./common").AuthnSession; valid?: boolean }
  | { ok: false; error: AuthnError };

export interface EnrollSMSParams {
  phoneNumber: string;
}

export type EnrollSMSResult =
  | { ok: true; message?: string; expiresInSeconds?: number }
  | { ok: false; error: AuthnError };

export interface SendSMSChallengeParams {
  /** The `mfaToken` the sign-in returned when it asked for a second factor. */
  mfaToken: string;
}

export type SendSMSChallengeResult =
  | {
      ok: true;
      /**
       * The destination, redacted to its country prefix and last two digits — enough to say
       * which handset to check without printing a number to a caller who has only the password.
       */
      phoneNumber?: string;
      expiresInSeconds?: number;
      message?: string;
    }
  | { ok: false; error: AuthnError };

export interface ConfirmSMSParams {
  code: string;
}

export interface DisableSMSParams {
  password?: string;
}

export interface RegenerateRecoveryCodesParams {
  password?: string;
}

export type RegenerateRecoveryCodesResult =
  | { ok: true; recoveryCodes: string[]; message?: string }
  | { ok: false; error: AuthnError };

export interface RecoveryCodesStatus {
  remainingCount: number;
  totalCount: number;
  hasRecoveryCodes: boolean;
}

export type RecoveryCodesStatusResult =
  | { ok: true; status: RecoveryCodesStatus }
  | { ok: false; error: AuthnError };

/** One enrolled second factor's state. */
export interface TwoFactorMethodState {
  /** Whether the factor is confirmed and usable. */
  enabled: boolean;
  /** When enrollment began. Absent when the factor is not enrolled. */
  createdAt?: string;
  /** When the factor last satisfied a verification. Absent if it never has. */
  lastUsedAt?: string;
}

/** The text-message factor, with the number codes are delivered to. */
export interface SMSMethodState extends TwoFactorMethodState {
  /**
   * The confirmed number, in full.
   *
   * Unredacted, unlike {@link SendSMSChallengeResult}'s: that one answers a caller who has proven
   * only the password, while this read needs a session — and the profile already returns the same
   * number to the same caller.
   */
  phoneNumber?: string;
}

export interface TwoFactorMethods {
  /**
   * What the next sign-in challenge will offer, most recently used first and `backup_code` last.
   * Empty when the account has no second factor.
   *
   * Distinct from the per-factor fields: `passkey` and `backup_code` appear here without a detail
   * object, because their own endpoints — `listWebAuthnCredentials` and `getRecoveryCodesStatus` —
   * carry the detail.
   */
  methods: string[];
  totp: TwoFactorMethodState;
  sms: SMSMethodState;
}

export type TwoFactorMethodsResult =
  | { ok: true; methods: TwoFactorMethods }
  | { ok: false; error: AuthnError };
