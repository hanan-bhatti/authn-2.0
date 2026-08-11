"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AuthnError,
  Confirm2FAResult,
  ConfirmSMSParams,
  ConfirmTOTPParams,
  DisableSMSParams,
  DisableTOTPParams,
  EnrollSMSParams,
  EnrollSMSResult,
  EnrollTOTPResult,
  RecoveryCodesStatusResult,
  RegenerateRecoveryCodesParams,
  RegenerateRecoveryCodesResult,
  VerifyTOTPParams,
  VerifyTOTPResult,
  VoidResult,
} from "@authn/js";
import { useAuthContext } from "../context";
import type { UseTOTPReturn } from "../types";

/**
 * Hook for 2FA TOTP, SMS OTP, and backup recovery codes management.
 *
 * All async handlers guard against calling setState after unmount (Finding 3.1).
 */
export function useTOTP(): UseTOTPReturn {
  const { client } = useAuthContext();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);

  // Prevents state updates on unmounted components (Finding 3.1 fix)
  const isMounted = useRef(true);
  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const reset = useCallback(() => {
    setError(null);
    setIsLoading(false);
  }, []);

  const enrollTOTP = useCallback(async (): Promise<EnrollTOTPResult> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.enrollTOTP();
      if (!result.ok && isMounted.current) {
        setError(result.error);
      }
      return result;
    } catch (err) {
      const authnError = err as AuthnError;
      if (isMounted.current) setError(authnError);
      return { ok: false, error: authnError };
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [client]);

  const confirmTOTP = useCallback(
    async (params: ConfirmTOTPParams): Promise<Confirm2FAResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.confirmTOTP(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const disableTOTP = useCallback(
    async (params: DisableTOTPParams): Promise<VoidResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.disableTOTP(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const verifyTOTP = useCallback(
    async (params: VerifyTOTPParams): Promise<VerifyTOTPResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.verifyTOTP(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const enrollSMS = useCallback(
    async (params: EnrollSMSParams): Promise<EnrollSMSResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.enrollSMS(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const confirmSMS = useCallback(
    async (params: ConfirmSMSParams): Promise<Confirm2FAResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.confirmSMS(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const disableSMS = useCallback(
    async (params: DisableSMSParams): Promise<VoidResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.disableSMS(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const regenerateRecoveryCodes = useCallback(
    async (
      params: RegenerateRecoveryCodesParams,
    ): Promise<RegenerateRecoveryCodesResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.regenerateRecoveryCodes(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const getRecoveryCodesStatus = useCallback(
    async (): Promise<RecoveryCodesStatusResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.getRecoveryCodesStatus();
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  return {
    enrollTOTP,
    confirmTOTP,
    disableTOTP,
    verifyTOTP,
    enrollSMS,
    confirmSMS,
    disableSMS,
    regenerateRecoveryCodes,
    getRecoveryCodesStatus,
    isLoading,
    error,
    reset,
  };
}
