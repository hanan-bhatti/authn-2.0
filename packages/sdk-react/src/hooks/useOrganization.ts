"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AcceptOrgInvitationParams,
  AcceptOrgInvitationResult,
  AuthnError,
  AuthnOrg,
  CreateOrgParams,
  CreateOrgResult,
  DeleteOrgResult,
  GetOrgResult,
  AuthnOrgInvitation,
  InviteOrgMemberParams,
  InviteOrgMemberResult,
  ListInvitationsResult,
  ListOrgsResult,
  RemoveOrgMemberResult,
  UpdateOrgParams,
  UpdateOrgResult,
} from "@authn/js";
import { useAuthContext } from "../context";

export interface UseOrganizationReturn {
  org: AuthnOrg | null;
  organizations: AuthnOrg[];
  /** Invitations addressed to the signed-in account, filled by `listInvitations`. */
  invitations: AuthnOrgInvitation[];
  isLoading: boolean;
  error: AuthnError | null;
  createOrg: (params: CreateOrgParams) => Promise<CreateOrgResult>;
  listOrgs: () => Promise<ListOrgsResult>;
  getOrg: (orgId: string) => Promise<GetOrgResult>;
  updateOrg: (orgId: string, params: UpdateOrgParams) => Promise<UpdateOrgResult>;
  deleteOrg: (orgId: string) => Promise<DeleteOrgResult>;
  inviteMember: (
    orgId: string,
    params: InviteOrgMemberParams,
  ) => Promise<InviteOrgMemberResult>;
  acceptInvitation: (
    params: AcceptOrgInvitationParams,
  ) => Promise<AcceptOrgInvitationResult>;
  listInvitations: () => Promise<ListInvitationsResult>;
  /**
   * Removes a member, or leaves when `userId` is the caller's own.
   *
   * A successful leave drops the organization from `organizations` here, since the
   * caller can no longer read it and a stale row would render controls that answer
   * 403.
   */
  removeMember: (orgId: string, userId: string) => Promise<RemoveOrgMemberResult>;
  reset: () => void;
}

/**
 * Hook for B2B Organization management: creation, listing, details, updating, deletion, and member invitations.
 *
 * All async handlers include `isMounted` guards to prevent memory leaks/state updates on unmounted components.
 */
export function useOrganization(initialOrgId?: string): UseOrganizationReturn {
  const { client } = useAuthContext();
  const [org, setOrg] = useState<AuthnOrg | null>(null);
  const [organizations, setOrganizations] = useState<AuthnOrg[]>([]);
  const [invitations, setInvitations] = useState<AuthnOrgInvitation[]>([]);
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

  const createOrg = useCallback(
    async (params: CreateOrgParams): Promise<CreateOrgResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.createOrganization(params);
        if (isMounted.current) {
          if (result.ok) {
            setOrg(result.org);
            setOrganizations((prev) => [...prev, result.org]);
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

  const listOrgs = useCallback(async (): Promise<ListOrgsResult> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.listOrganizations();
      if (isMounted.current) {
        if (result.ok) {
          setOrganizations(result.organizations);
        } else {
          setError(result.error);
        }
      }
      return result;
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [client]);

  const getOrg = useCallback(
    async (orgId: string): Promise<GetOrgResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.getOrganization(orgId);
        if (isMounted.current) {
          if (result.ok) {
            setOrg(result.org);
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

  const updateOrg = useCallback(
    async (orgId: string, params: UpdateOrgParams): Promise<UpdateOrgResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.updateOrganization(orgId, params);
        if (isMounted.current) {
          if (result.ok) {
            setOrg(result.org);
            setOrganizations((prev) =>
              prev.map((o) => (o.id === orgId ? result.org : o)),
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
    [client],
  );

  const deleteOrg = useCallback(
    async (orgId: string): Promise<DeleteOrgResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.deleteOrganization(orgId);
        if (isMounted.current) {
          if (result.ok) {
            if (org?.id === orgId) setOrg(null);
            setOrganizations((prev) => prev.filter((o) => o.id !== orgId));
          } else {
            setError(result.error);
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client, org?.id],
  );

  const inviteMember = useCallback(
    async (
      orgId: string,
      params: InviteOrgMemberParams,
    ): Promise<InviteOrgMemberResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.inviteOrgMember(orgId, params);
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

  const acceptInvitation = useCallback(
    async (
      params: AcceptOrgInvitationParams,
    ): Promise<AcceptOrgInvitationResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.acceptOrgInvitation(params);
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

  const listInvitations = useCallback(async (): Promise<ListInvitationsResult> => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await client.listInvitations();
      if (isMounted.current) {
        if (result.ok) {
          setInvitations(result.invitations);
        } else {
          setError(result.error);
        }
      }
      return result;
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [client]);

  const removeMember = useCallback(
    async (orgId: string, userId: string): Promise<RemoveOrgMemberResult> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await client.removeOrgMember(orgId, userId);
        if (isMounted.current) {
          if (!result.ok) {
            setError(result.error);
          } else if (result.left) {
            if (org?.id === orgId) setOrg(null);
            setOrganizations((prev) => prev.filter((o) => o.id !== orgId));
          }
        }
        return result;
      } finally {
        if (isMounted.current) setIsLoading(false);
      }
    },
    [client, org?.id],
  );

  useEffect(() => {
    if (initialOrgId) {
      getOrg(initialOrgId);
    }
  }, [initialOrgId, getOrg]);

  return {
    org,
    organizations,
    invitations,
    isLoading,
    error,
    createOrg,
    listOrgs,
    getOrg,
    updateOrg,
    deleteOrg,
    inviteMember,
    acceptInvitation,
    listInvitations,
    removeMember,
    reset,
  };
}
