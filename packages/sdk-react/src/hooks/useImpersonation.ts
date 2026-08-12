/**
 * @authn/react — useImpersonation Hook
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { AuthnAdminClient } from "@authn/js/admin";
import type {
  InitiateImpersonationParams,
  ImpersonationPolicyDTO,
  UpdateImpersonationPolicyParams,
} from "@authn/js/admin";
import { AuthnError, AuthnErrorCode } from "@authn/js";

export interface UseImpersonationReturn {
  policy: ImpersonationPolicyDTO | null;
  impersonationToken: string | null;
  isLoading: boolean;
  error: AuthnError | null;
  impersonateUser: (params: InitiateImpersonationParams) => Promise<string | null>;
  exitImpersonation: (token: string) => Promise<boolean>;
  getImpersonationPolicy: () => Promise<ImpersonationPolicyDTO | null>;
  updateImpersonationPolicy: (
    params: UpdateImpersonationPolicyParams
  ) => Promise<ImpersonationPolicyDTO | null>;
  reset: () => void;
}

export function useImpersonation(
  adminClient?: AuthnAdminClient
): UseImpersonationReturn {
  const [policy, setPolicy] = useState<ImpersonationPolicyDTO | null>(null);
  const [impersonationToken, setImpersonationToken] = useState<string | null>(
    null
  );
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const isMounted = useRef(true);
  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const reset = useCallback(() => {
    setPolicy(null);
    setImpersonationToken(null);
    setIsLoading(false);
    setError(null);
  }, []);

  const impersonateUser = useCallback(
    async (params: InitiateImpersonationParams): Promise<string | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.impersonateUser(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setImpersonationToken(res.impersonationToken);
          return res.impersonationToken;
        } else {
          setError(res.error);
          return null;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error
                  ? err.message
                  : "Failed to initiate impersonation",
            })
          );
        }
        return null;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  const exitImpersonation = useCallback(
    async (token: string): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.exitImpersonation(token);
        if (!isMounted.current) return false;
        if (res.ok) {
          setImpersonationToken(null);
          return true;
        } else {
          setError(res.error);
          return false;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error
                  ? err.message
                  : "Failed to exit impersonation",
            })
          );
        }
        return false;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  const getImpersonationPolicy = useCallback(async (): Promise<ImpersonationPolicyDTO | null> => {
    if (!adminClient) return null;
    setIsLoading(true);
    setError(null);
    try {
      const res = await adminClient.getImpersonationPolicy();
      if (!isMounted.current) return null;
      if (res.ok) {
        setPolicy(res.policy);
        return res.policy;
      } else {
        setError(res.error);
        return null;
      }
    } catch (err) {
      if (isMounted.current) {
        setError(
          new AuthnError({
            code: AuthnErrorCode.UNKNOWN,
            message:
              err instanceof Error
                ? err.message
                : "Failed to get impersonation policy",
          })
        );
      }
      return null;
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [adminClient]);

  const updateImpersonationPolicy = useCallback(
    async (
      params: UpdateImpersonationPolicyParams
    ): Promise<ImpersonationPolicyDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.updateImpersonationPolicy(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setPolicy(res.policy);
          return res.policy;
        } else {
          setError(res.error);
          return null;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error
                  ? err.message
                  : "Failed to update impersonation policy",
            })
          );
        }
        return null;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  return {
    policy,
    impersonationToken,
    isLoading,
    error,
    impersonateUser,
    exitImpersonation,
    getImpersonationPolicy,
    updateImpersonationPolicy,
    reset,
  };
}
