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
