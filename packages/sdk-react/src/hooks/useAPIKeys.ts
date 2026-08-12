/**
 * @authn/react — useAPIKeys Hook
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { AuthnAdminClient } from "@authn/js/admin";
import type { APIKeyDTO, CreateAPIKeyParams } from "@authn/js/admin";
import { AuthnError, AuthnErrorCode } from "@authn/js";

export interface UseAPIKeysReturn {
  keys: APIKeyDTO[];
  isLoading: boolean;
  error: AuthnError | null;
  listKeys: () => Promise<void>;
  createKey: (params: CreateAPIKeyParams) => Promise<APIKeyDTO | null>;
  revokeKey: (keyId: string) => Promise<boolean>;
  reset: () => void;
}

export function useAPIKeys(adminClient?: AuthnAdminClient): UseAPIKeysReturn {
  const [keys, setKeys] = useState<APIKeyDTO[]>([]);
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
    setKeys([]);
    setIsLoading(false);
    setError(null);
  }, []);

  const listKeys = useCallback(async () => {
    if (!adminClient) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await adminClient.listAPIKeys();
      if (!isMounted.current) return;
      if (res.ok) {
        setKeys(res.keys);
      } else {
        setError(res.error);
      }
    } catch (err) {
      if (isMounted.current) {
        setError(
          new AuthnError({
            code: AuthnErrorCode.UNKNOWN,
            message: err instanceof Error ? err.message : "Failed to list API keys",
          })
        );
      }
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [adminClient]);

  const createKey = useCallback(
    async (params: CreateAPIKeyParams): Promise<APIKeyDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.createAPIKey(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setKeys((prev) => [...prev, res.key]);
          return res.key;
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
                err instanceof Error ? err.message : "Failed to create API key",
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

  const revokeKey = useCallback(
    async (keyId: string): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.revokeAPIKey(keyId);
        if (!isMounted.current) return false;
        if (res.ok) {
          setKeys((prev) =>
            prev.map((k) =>
              k.id === keyId ? { ...k, revokedAt: new Date().toISOString() } : k
            )
          );
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
                err instanceof Error ? err.message : "Failed to revoke API key",
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

  return {
    keys,
    isLoading,
    error,
    listKeys,
    createKey,
    revokeKey,
    reset,
  };
}
