/**
 * @authn/react — useSAML Hook
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { AuthnAdminClient } from "@authn/js/admin";
import type {
  SAMLConnectionDTO,
  CreateSAMLConnectionParams,
  UpdateSAMLConnectionParams,
} from "@authn/js/admin";
import { AuthnError, AuthnErrorCode } from "@authn/js";

export interface UseSAMLReturn {
  connection: SAMLConnectionDTO | null;
  isLoading: boolean;
  error: AuthnError | null;
  createConnection: (
    params: CreateSAMLConnectionParams
  ) => Promise<SAMLConnectionDTO | null>;
  getConnection: (orgId: string) => Promise<SAMLConnectionDTO | null>;
  updateConnection: (
    params: UpdateSAMLConnectionParams
  ) => Promise<SAMLConnectionDTO | null>;
  deleteConnection: (orgId: string) => Promise<boolean>;
  reset: () => void;
}

export function useSAML(adminClient?: AuthnAdminClient): UseSAMLReturn {
  const [connection, setConnection] = useState<SAMLConnectionDTO | null>(null);
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
    setConnection(null);
    setIsLoading(false);
    setError(null);
  }, []);

  const createConnection = useCallback(
    async (
      params: CreateSAMLConnectionParams
    ): Promise<SAMLConnectionDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.createSAMLConnection(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setConnection(res.connection);
          return res.connection;
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
                  : "Failed to create SAML connection",
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

  const getConnection = useCallback(
    async (orgId: string): Promise<SAMLConnectionDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.getSAMLConnection(orgId);
        if (!isMounted.current) return null;
        if (res.ok) {
          setConnection(res.connection);
          return res.connection;
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
                  : "Failed to get SAML connection",
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

  const updateConnection = useCallback(
    async (
      params: UpdateSAMLConnectionParams
    ): Promise<SAMLConnectionDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.updateSAMLConnection(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setConnection(res.connection);
          return res.connection;
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
                  : "Failed to update SAML connection",
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

  const deleteConnection = useCallback(
    async (orgId: string): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.deleteSAMLConnection(orgId);
        if (!isMounted.current) return false;
        if (res.ok) {
          setConnection(null);
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
                  : "Failed to delete SAML connection",
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
    connection,
    isLoading,
    error,
    createConnection,
    getConnection,
    updateConnection,
    deleteConnection,
    reset,
  };
}
