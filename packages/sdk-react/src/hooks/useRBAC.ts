/**
 * @authn/react — useRBAC Hook
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { AuthnAdminClient } from "@authn/js/admin";
import type {
  RoleDTO,
  CreateRoleParams,
  UpdateRolePermissionsParams,
  AssignUserRoleParams,
  RevokeUserRoleParams,
} from "@authn/js/admin";
import { AuthnError, AuthnErrorCode } from "@authn/js";

export interface UseRBACReturn {
  roles: RoleDTO[];
  userPermissions: string[];
  isLoading: boolean;
  error: AuthnError | null;
  listRoles: () => Promise<void>;
  createRole: (params: CreateRoleParams) => Promise<RoleDTO | null>;
  updateRolePermissions: (params: UpdateRolePermissionsParams) => Promise<RoleDTO | null>;
  assignUserRole: (params: AssignUserRoleParams) => Promise<boolean>;
  revokeUserRole: (params: RevokeUserRoleParams) => Promise<boolean>;
  getUserPermissions: () => Promise<string[] | null>;
  reset: () => void;
}

export function useRBAC(adminClient?: AuthnAdminClient): UseRBACReturn {
  const [roles, setRoles] = useState<RoleDTO[]>([]);
  const [userPermissions, setUserPermissions] = useState<string[]>([]);
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
    setRoles([]);
    setUserPermissions([]);
    setIsLoading(false);
    setError(null);
  }, []);

  const listRoles = useCallback(async () => {
    if (!adminClient) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await adminClient.listRoles();
      if (!isMounted.current) return;
      if (res.ok) {
        setRoles(res.roles);
      } else {
        setError(res.error);
      }
    } catch (err) {
      if (isMounted.current) {
        setError(
          new AuthnError({
            code: AuthnErrorCode.UNKNOWN,
            message: err instanceof Error ? err.message : "Failed to list roles",
          })
        );
      }
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [adminClient]);

  const createRole = useCallback(
    async (params: CreateRoleParams): Promise<RoleDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.createRole(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setRoles((prev) => [...prev, res.role]);
          return res.role;
        } else {
          setError(res.error);
          return null;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message: err instanceof Error ? err.message : "Failed to create role",
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

  const updateRolePermissions = useCallback(
    async (params: UpdateRolePermissionsParams): Promise<RoleDTO | null> => {
      if (!adminClient) return null;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.updateRolePermissions(params);
        if (!isMounted.current) return null;
        if (res.ok) {
          setRoles((prev) =>
            prev.map((r) => (r.id === res.role.id ? res.role : r))
          );
          return res.role;
        } else {
          setError(res.error);
          return null;
        }
      } catch (err) {
        if (isMounted.current) {
          setError(
            new AuthnError({
              code: AuthnErrorCode.UNKNOWN,
              message: err instanceof Error ? err.message : "Failed to update role permissions",
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

  const assignUserRole = useCallback(
    async (params: AssignUserRoleParams): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.assignUserRole(params);
        if (!isMounted.current) return false;
        if (res.ok) {
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
              message: err instanceof Error ? err.message : "Failed to assign user role",
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

  const revokeUserRole = useCallback(
    async (params: RevokeUserRoleParams): Promise<boolean> => {
      if (!adminClient) return false;
      setIsLoading(true);
      setError(null);
      try {
        const res = await adminClient.revokeUserRole(params);
        if (!isMounted.current) return false;
        if (res.ok) {
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
              message: err instanceof Error ? err.message : "Failed to revoke user role",
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

  const getUserPermissions = useCallback(async (): Promise<string[] | null> => {
    if (!adminClient) return null;
    setIsLoading(true);
    setError(null);
    try {
      const res = await adminClient.getUserPermissions();
      if (!isMounted.current) return null;
      if (res.ok) {
        setUserPermissions(res.permissions);
        return res.permissions;
      } else {
        setError(res.error);
        return null;
      }
    } catch (err) {
      if (isMounted.current) {
        setError(
          new AuthnError({
            code: AuthnErrorCode.UNKNOWN,
            message: err instanceof Error ? err.message : "Failed to get user permissions",
          })
        );
      }
      return null;
    } finally {
      if (isMounted.current) setIsLoading(false);
    }
  }, [adminClient]);

  return {
    roles,
    userPermissions,
    isLoading,
    error,
    listRoles,
    createRole,
    updateRolePermissions,
    assignUserRole,
    revokeUserRole,
    getUserPermissions,
    reset,
  };
}
