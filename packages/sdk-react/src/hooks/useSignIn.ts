"use client";

import { useCallback, useState } from "react";
import type { AuthnError, AuthResult, LoginParams } from "@authn/js";
import { useAuthContext } from "../context";
import type { UseSignInReturn } from "../types";

/**
 * Hook for email/password sign-in with managed loading and error state.
 */
export function useSignIn(): UseSignInReturn {
  const { client } = useAuthContext();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const reset = useCallback(() => {
    setError(null);
    setIsLoading(false);
  }, []);

  const signIn = useCallback(
    async (params: LoginParams): Promise<AuthResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.login(params);
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

  return { signIn, isLoading, error, reset };
}
