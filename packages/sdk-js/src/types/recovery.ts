import type { AuthnError } from "./errors";
import type { SecurityQuestion } from "./securityquestions";

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
      /**
       * The prompts to ask, present only when `availableMethods` includes
       * `security_questions`.
       *
       * They travel with the offer because a locked-out caller has no session and
       * so no other route to them: a method offered without its questions cannot be
       * attempted. Their absence is not an account-existence signal — the decoy
       * response for an address with no account never offers this method either.
       */
      securityQuestions?: SecurityQuestion[];
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
