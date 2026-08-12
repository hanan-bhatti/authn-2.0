/**
 * @authn/react — useAuditLogs Hook
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { AuthnAdminClient } from "@authn/js/admin";
import type { AuditLogDTO, ListAuditLogsParams } from "@authn/js/admin";
import { AuthnError, AuthnErrorCode } from "@authn/js";

export interface UseAuditLogsReturn {
  logs: AuditLogDTO[];
  total: number;
  isLoading: boolean;
  error: AuthnError | null;
  listLogs: (params?: ListAuditLogsParams) => Promise<void>;
  reset: () => void;
}

export function useAuditLogs(adminClient?: AuthnAdminClient): UseAuditLogsReturn {
  const [logs, setLogs] = useState<AuditLogDTO[]>([]);
  const [total, setTotal] = useState<number>(0);
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
    setLogs([]);
    setTotal(0);
    setIsLoading(false);
    setError(null);
  }, []);

  const listLogs = useCallback(
    async (params?: ListAuditLogsParams) => {
      if (!adminClient) return;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.listAuditLogs(params);
        if (!isMounted.current) return;
        if (res.ok) {
          setLogs(res.logs);
          setTotal(res.total);
        } else {
          setError(res.error);
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message:
                err instanceof Error ? err.message : "Failed to list audit logs",
            })
          );
        }
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [adminClient]
  );

  return {
    logs,
    total,
    isLoading,
    error,
    listLogs,
    reset,
  };
}
