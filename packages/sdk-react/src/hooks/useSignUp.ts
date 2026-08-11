"use client";

import { useCallback, useState } from "react";
import type { AuthnError, AuthResult, SignUpParams } from "@authn/js";
import { useAuthContext } from "../context";
import type { UseSignUpReturn } from "../types";

/**
 * Hook for email/password sign-up with managed loading and error state.
 */
export function useSignUp(): UseSignUpReturn {
  const { client } = useAuthContext();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const reset = useCallback(() => {
    setError(null);
    setIsLoading(false);
  }, []);

  const signUp = useCallback(
    async (params: SignUpParams): Promise<AuthResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.signUp(params);
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

  return { signUp, isLoading, error, reset };
}
