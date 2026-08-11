"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AcceptGuardianInviteParams,
  AcceptGuardianInviteResult,
  AuthnError,
  AuthnGuardian,
  InviteGuardiansParams,
  InviteGuardiansResult,
  ListGuardiansResult,
  RevokeGuardianResult,
} from "@authn/js";
import { useAuthContext } from "../context";

export interface UseGuardiansReturn {
  guardians: AuthnGuardian[];
  isLoading: boolean;
  error: AuthnError | null;
  inviteGuardians: (
    params: InviteGuardiansParams,
  ) => Promise<InviteGuardiansResult>;
  acceptGuardianInvite: (
    params: AcceptGuardianInviteParams,
  ) => Promise<AcceptGuardianInviteResult>;
  listGuardians: () => Promise<ListGuardiansResult>;
  revokeGuardian: (contactId: string) => Promise<RevokeGuardianResult>;
  reset: () => void;
}

/**
 * Hook for social recovery guardian roster management.
 *
 * All async handlers include `isMounted` guards to prevent state updates on unmounted components.
 */
export function useGuardians(): UseGuardiansReturn {
  const { client } = useAuthContext();
  const [guardians, setGuardians] = useState<AuthnGuardian[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<AuthnError | null>(null);

  const isMounted = useRef(true);
  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const reset = useCallback(() => {
    setError(null);
    setIsLoading(false);
  }, []);

  const inviteGuardians = useCallback(
    async (
      params: InviteGuardiansParams,
    ): Promise<InviteGuardiansResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.inviteGuardians(params);
        if (isMounted.current) {
          if (result.ok) {
            setGuardians((prev) => [...prev, ...result.guardians]);
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const acceptGuardianInvite = useCallback(
    async (
      params: AcceptGuardianInviteParams,
    ): Promise<AcceptGuardianInviteResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.acceptGuardianInvite(params);
        if (isMounted.current && !result.ok) {
          setError(result.error);
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  const listGuardians = useCallback(async (): Promise<ListGuardiansResult> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.listGuardians();
      if (isMounted.current) {
        if (result.ok) {
          setGuardians(result.guardians);
        } else {
          setError(result.error);
        }
      }
      return result;
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [client]);

  const revokeGuardian = useCallback(
    async (contactId: string): Promise<RevokeGuardianResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.revokeGuardian(contactId);
        if (isMounted.current) {
          if (result.ok) {
            setGuardians((prev) => prev.filter((g) => g.id !== contactId));
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client],
  );

  return {
    guardians,
    isLoading,
    error,
    inviteGuardians,
    acceptGuardianInvite,
    listGuardians,
    revokeGuardian,
    reset,
  };
}
