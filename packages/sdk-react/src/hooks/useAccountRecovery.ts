"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AuthnError,
  CancelRecoveryParams,
  CancelRecoveryResult,
  CancelRecoveryTokenParams,
  CancelRecoveryTokenResult,
  ClaimAccountParams,
  ClaimAccountResult,
  InitiateRecoveryParams,
  InitiateRecoveryResult,
  SecurityQuestion,
  SubmitGuardianProofParams,
  SubmitGuardianProofResult,
  SubmitOldPasswordProofParams,
  SubmitOldPasswordProofResult,
  SubmitSecurityQuestionsProofParams,
  SubmitSecurityQuestionsProofResult,
} from "@authn/js";
import { useAuthContext } from "../context";

export interface UseAccountRecoveryReturn {
  recoveryRequestId: string | null;
  status: string | null;
  availableMethods: string[];
  /**
   * The prompts to ask, populated by `initiateRecovery` when
   * `availableMethods` includes `security_questions` and empty otherwise.
   *
   * Held here rather than read from the initiate response because that response is
   * the only place they appear: a locked-out caller has no session, so there is no
   * second endpoint to fetch them from if the component that made the call drops
   * them.
   */
  securityQuestions: SecurityQuestion[];
  isTrustedDeviceOrigin: boolean;
  isLoading: boolean;
  error: AuthnError | null;
  initiateRecovery: (
    params: InitiateRecoveryParams,
  ) => Promise<InitiateRecoveryResult>;
  submitGuardianProof: (
    params: SubmitGuardianProofParams,
  ) => Promise<SubmitGuardianProofResult>;
  submitOldPasswordProof: (
    params: SubmitOldPasswordProofParams,
  ) => Promise<SubmitOldPasswordProofResult>;
  submitSecurityQuestionsProof: (
    params: SubmitSecurityQuestionsProofParams,
  ) => Promise<SubmitSecurityQuestionsProofResult>;
  claimAccount: (params: ClaimAccountParams) => Promise<ClaimAccountResult>;
  cancelRecovery: (
    params: CancelRecoveryParams,
  ) => Promise<CancelRecoveryResult>;
  cancelRecoveryToken: (
    params: CancelRecoveryTokenParams,
  ) => Promise<CancelRecoveryTokenResult>;
  reset: () => void;
}

/**
 * Hook for account recovery workflows (initiation, proofs, claim, and cancellation).
 *
 * All async handlers include `isMounted` guards to prevent state updates on unmounted components.
 */
export function useAccountRecovery(): UseAccountRecoveryReturn {
  const { client } = useAuthContext();
  const [recoveryRequestId, setRecoveryRequestId] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [availableMethods, setAvailableMethods] = useState<string[]>([]);
  const [securityQuestions, setSecurityQuestions] = useState<SecurityQuestion[]>([]);
  const [isTrustedDeviceOrigin, setIsTrustedDeviceOrigin] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const isMounted = useRef(true);
  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const reset = useCallback(() => {
    setRecoveryRequestId(null);
    setStatus(null);
    setAvailableMethods([]);
    setSecurityQuestions([]);
    setIsTrustedDeviceOrigin(false);
    setError(null);
    setIsLoading(false);
  }, []);

  const initiateRecovery = useCallback(
    async (
      params: InitiateRecoveryParams,
    ): Promise<InitiateRecoveryResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.initiateRecovery(params);
        if (isMounted.current) {
          if (result.ok) {
            setRecoveryRequestId(result.recoveryRequestId);
            setStatus(result.status);
            setAvailableMethods(result.availableMethods);
            setSecurityQuestions(result.securityQuestions ?? []);
            setIsTrustedDeviceOrigin(result.isTrustedDeviceOrigin);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const submitGuardianProof = useCallback(
    async (
      params: SubmitGuardianProofParams,
    ): Promise<SubmitGuardianProofResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.submitGuardianProof(params);
        if (isMounted.current) {
          if (result.ok) {
            setStatus(result.status);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const submitOldPasswordProof = useCallback(
    async (
      params: SubmitOldPasswordProofParams,
    ): Promise<SubmitOldPasswordProofResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.submitOldPasswordProof(params);
        if (isMounted.current) {
          if (result.ok) {
            setStatus(result.status);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const submitSecurityQuestionsProof = useCallback(
    async (
      params: SubmitSecurityQuestionsProofParams,
    ): Promise<SubmitSecurityQuestionsProofResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.submitSecurityQuestionsProof(params);
        if (isMounted.current) {
          if (result.ok) {
            setStatus(result.status);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const claimAccount = useCallback(
    async (params: ClaimAccountParams): Promise<ClaimAccountResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.claimAccount(params);
        if (isMounted.current) {
          if (result.ok) {
            setStatus(result.status);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const cancelRecovery = useCallback(
    async (
      params: CancelRecoveryParams,
    ): Promise<CancelRecoveryResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.cancelRecovery(params);
        if (isMounted.current) {
          if (result.ok) {
            setStatus(result.status);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const cancelRecoveryToken = useCallback(
    async (
      params: CancelRecoveryTokenParams,
    ): Promise<CancelRecoveryTokenResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.cancelRecoveryToken(params);
        if (isMounted.current) {
          if (result.ok) {
            setStatus(result.status);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  return {
    recoveryRequestId,
    status,
    availableMethods,
    securityQuestions,
    isTrustedDeviceOrigin,
    isLoading,
    error,
    initiateRecovery,
    submitGuardianProof,
    submitOldPasswordProof,
    submitSecurityQuestionsProof,
    claimAccount,
    cancelRecovery,
    cancelRecoveryToken,
    reset,
  };
}
