import type { AuthnError } from "./errors";

export interface InitiateRecoveryParams {
  email: string;
  tenantId?: string;
  environment?: string;
}

export type InitiateRecoveryResult =
  | {
      ok: true;
      recoveryRequestId: string;
      status: string;
      isTrustedDeviceOrigin: boolean;
      availableMethods: string[];
    }
  | { ok: false; error: AuthnError };

export interface SubmitGuardianProofParams {
  recoveryRequestId: string;
  sharePayload: string;
}

export type SubmitGuardianProofResult =
  | { ok: true; thresholdReached: boolean; status: string }
  | { ok: false; error: AuthnError };

export interface SubmitOldPasswordProofParams {
  recoveryRequestId: string;
  password: string;
}

export type SubmitOldPasswordProofResult =
  | { ok: true; status: string; message: string }
  | { ok: false; error: AuthnError };

export interface SubmitSecurityQuestionsProofParams {
  recoveryRequestId: string;
  answers: Record<string, string>;
}

export type SubmitSecurityQuestionsProofResult =
  | { ok: true; status: string; message: string }
  | { ok: false; error: AuthnError };

export interface ClaimAccountParams {
  requestId: string;
  claimToken: string;
  newPassword: string;
}

export type ClaimAccountResult =
  | {
      ok: true;
      status: string;
      message: string;
      recoveryCodes: string[];
      deviceCookie?: string;
    }
  | { ok: false; error: AuthnError };

export interface CancelRecoveryParams {
  recoveryRequestId: string;
}

export type CancelRecoveryResult =
  | { ok: true; status: string; message: string }
  | { ok: false; error: AuthnError };

export interface CancelRecoveryTokenParams {
  cancellationToken: string;
}

export type CancelRecoveryTokenResult =
  | { ok: true; status: string; message: string }
  | { ok: false; error: AuthnError };
