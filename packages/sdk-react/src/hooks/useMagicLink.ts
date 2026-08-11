"use client";

import { useCallback, useState } from "react";
import type {
  AuthnError,
  AuthResult,
  MagicLinkParams,
  VerifyMagicLinkParams,
  VoidResult,
} from "@authn/js";
import { useAuthContext } from "../context";
import type { UseMagicLinkReturn } from "../types";

/**
 * Hook for passwordless magic link request and verification.
 */
export function useMagicLink(): UseMagicLinkReturn {
  const { client } = useAuthContext();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const reset = useCallback(() => {
    setError(null);
    setIsLoading(false);
  }, []);

  const sendMagicLink = useCallback(
    async (params: MagicLinkParams): Promise<VoidResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.sendMagicLink(params);
        if (!result.ok) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        setIsLoading(false);
      }
    },
    [client],
  );

  const verifyMagicLink = useCallback(
    async (params: VerifyMagicLinkParams): Promise<AuthResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.verifyMagicLink(params);
        if (!result.ok) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        setIsLoading(false);
      }
    },
    [client],
  );

  return { sendMagicLink, verifyMagicLink, isLoading, error, reset };
}
