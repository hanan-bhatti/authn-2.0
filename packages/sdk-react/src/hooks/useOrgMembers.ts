"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  AuthnError,
  type AuthnOrgMember,
  type ListOrgMembersResult,
  type UpdateOrgMemberRoleParams,
  type UpdateOrgMemberRoleResult,
} from "@authn/js";
import { useAuthContext } from "../context";

export interface UseOrgMembersReturn {
  members: AuthnOrgMember[];
  total: number;
  isLoading: boolean;
  error: AuthnError | null;
  listMembers: () => Promise<ListOrgMembersResult>;
  updateMemberRole: (
    userId: string,
    params: UpdateOrgMemberRoleParams,
  ) => Promise<UpdateOrgMemberRoleResult>;
  reset: () => void;
}

/**
 * Hook for managing organization team members and their roles.
 *
 * All async handlers include `isMounted` guards to prevent memory leaks/state updates on unmounted components.
 */
export function useOrgMembers(orgId: string): UseOrgMembersReturn {
  const { client } = useAuthContext();
  const [members, setMembers] = useState<AuthnOrgMember[]>([]);
  const [total, setTotal] = useState<number>(0);
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

  const listMembers = useCallback(async (): Promise<ListOrgMembersResult> => {
    if (!orgId) {
      return {
        ok: false,
        error: AuthnError.validation("orgId", "orgId is required to list members"),
      };
    }
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.listOrgMembers(orgId);
      if (isMounted.current) {
        if (result.ok) {
          setMembers(result.members);
          setTotal(result.total);
        } else {
          setError(result.error);
        }
      }
      return result;
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [client, orgId]);

  const updateMemberRole = useCallback(
    async (
      userId: string,
      params: UpdateOrgMemberRoleParams,
    ): Promise<UpdateOrgMemberRoleResult> => {
      if (!orgId) {
        return {
          ok: false,
          error: AuthnError.validation("orgId", "orgId is required to update member role"),
        };
      }
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.updateOrgMemberRole(orgId, userId, params);
        if (isMounted.current) {
          if (result.ok) {
            setMembers((prev) =>
              prev.map((m) => (m.userId === userId ? result.member : m)),
            );
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client, orgId],
  );

  useEffect(() => {
    if (orgId) {
      listMembers();
    }
  }, [orgId, listMembers]);

  return {
    members,
    total,
    isLoading,
    error,
    listMembers,
    updateMemberRole,
    reset,
  };
}
