"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AuthnError,
  BeginPasskeyLoginParams,
  BeginPasskeyLoginResult,
  BeginPasskeyRegistrationResult,
  Confirm2FAResult,
  FinishPasskeyLoginParams,
  FinishPasskeyLoginResult,
  FinishPasskeyRegistrationParams,
  ListWebAuthnCredentialsResult,
  RevokeWebAuthnCredentialParams,
  VoidResult,
  WebAuthnPasskey,
} from "@authn/js";
import { useAuthContext } from "../context";
import type { UsePasskeysReturn } from "../types";

/**
 * Hook for WebAuthn Passkeys (FIDO2 registration, assertion login, and management).
 *
 * All async handlers guard against calling setState after unmount (Finding 3.1).
 * The `inFlight` ref prevents concurrent begin→finish race conditions (Finding 3.1 race).
 */
export function usePasskeys(): UsePasskeysReturn {
  const { client } = useAuthContext();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);
  const [credentials, setCredentials] = useState<WebAuthnPasskey[]>([]);

  // Prevents state updates on unmounted components (Finding 3.1 fix)
  const isMounted = useRef(true);
  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  // Prevents concurrent begin→finish race: only one passkey operation at a time
  const inFlight = useRef(false);

  const reset = useCallback(() => {
    setError(null);
    setIsLoading(false);
  }, []);

  const registerPasskey = useCallback(
    async (name?: string): Promise<Confirm2FAResult> => {
      if (inFlight.current) {
        return {
          ok: false,
          error: { message: "A passkey operation is already in progress." } as AuthnError,
        };
      }
      inFlight.current = true;
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.registerPasskey(name);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        inFlight.current = false;
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const loginWithPasskey = useCallback(
    async (mfaToken: string): Promise<FinishPasskeyLoginResult> => {
      if (inFlight.current) {
        return {
          ok: false,
          error: { message: "A passkey operation is already in progress." } as AuthnError,
        };
      }
      inFlight.current = true;
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.loginWithPasskey(mfaToken);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        inFlight.current = false;
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const listCredentials = useCallback(async (): Promise<ListWebAuthnCredentialsResult> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.listWebAuthnCredentials();
      if (result.ok) {
        if (isMounted.current) setCredentials(result.credentials);
      } else {
        if (isMounted.current) setError(result.error);
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

  const revokeCredential = useCallback(
    async (params: RevokeWebAuthnCredentialParams): Promise<VoidResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.revokeWebAuthnCredential(params);
        if (result.ok) {
          if (isMounted.current) setCredentials((prev) => prev.filter((c) => c.id !== params.id));
        } else {
          if (isMounted.current) setError(result.error);
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

  const beginRegistration = useCallback(async (): Promise<BeginPasskeyRegistrationResult> => {
    if (inFlight.current) {
      return {
        ok: false,
        error: { message: "A passkey operation is already in progress." } as AuthnError,
      };
    }
    inFlight.current = true;
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.beginPasskeyRegistration();
      if (!result.ok && isMounted.current) {
        setError(result.error);
      }
      return result;
    } catch (err) {
      const authnError = err as AuthnError;
      if (isMounted.current) setError(authnError);
      return { ok: false, error: authnError };
    } finally {
      inFlight.current = false;
      if (isMounted.current) setIsLoading(false);
    }
  }, [client]);

  const finishRegistration = useCallback(
    async (params: FinishPasskeyRegistrationParams): Promise<Confirm2FAResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.finishPasskeyRegistration(params);
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

  const beginLogin = useCallback(
    async (params: BeginPasskeyLoginParams): Promise<BeginPasskeyLoginResult> => {
      if (inFlight.current) {
        return {
          ok: false,
          error: { message: "A passkey operation is already in progress." } as AuthnError,
        };
      }
      inFlight.current = true;
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.beginPasskeyLogin(params);
        if (!result.ok && isMounted.current) {
          setError(result.error);
        }
        return result;
      } catch (err) {
        const authnError = err as AuthnError;
        if (isMounted.current) setError(authnError);
        return { ok: false, error: authnError };
      } finally {
        inFlight.current = false;
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const finishLogin = useCallback(
    async (params: FinishPasskeyLoginParams): Promise<FinishPasskeyLoginResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.finishPasskeyLogin(params);
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
    registerPasskey,
    loginWithPasskey,
    listCredentials,
    revokeCredential,
    beginRegistration,
    finishRegistration,
    beginLogin,
    finishLogin,
    credentials,
    isLoading,
    error,
    reset,
  };
}
