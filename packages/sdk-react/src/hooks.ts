import { useCallback, useState } from "react";
import type {
  AuthnError,
  AuthnUser,
  AuthResult,
  LoginParams,
  MagicLinkParams,
  SignUpParams,
  VerifyMagicLinkParams,
  VoidResult,
} from "@authn/js";
import { useAuthContext } from "./context";
import type {
  UseAuthReturn,
  UseMagicLinkReturn,
  UseSignInReturn,
  UseSignOutReturn,
  UseSignUpReturn,
} from "./types";

/**
 * Access the current authentication state and core AuthnClient instance.
 *
 * Must be used inside `<AuthnProvider>`.
 */
export function useAuth(): UseAuthReturn {
  return useAuthContext();
}

/**
 * Access the active authenticated user, or `null` if unauthenticated.
 *
 * Convenience wrapper around `useAuth().user`.
 */
export function useUser(): AuthnUser | null {
  return useAuthContext().user;
}

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
        // Unexpected errors returned as AuthnError
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
