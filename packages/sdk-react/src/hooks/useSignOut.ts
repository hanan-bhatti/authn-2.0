"use client";

import { useCallback, useState } from "react";
import type { AuthnError, VoidResult } from "@authn/js";
import { useAuthContext } from "../context";
import type { UseSignOutReturn } from "../types";

/**
 * Hook for sign-out with managed loading and error state.
 */
export function useSignOut(): UseSignOutReturn {
  const { client } = useAuthContext();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const reset = useCallback(() => {
    setError(null);
    setIsLoading(false);
  }, []);

  const signOut = useCallback(async (): Promise<VoidResult> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.signOut();
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
  }, [client]);

  return { signOut, isLoading, error, reset };
}
