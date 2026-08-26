"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  type ReactNode,
} from "react";
import { useAuth } from "@authn/react";
import type { AuthnError, AuthnOrg } from "@authn/js";
import { useResource, type ResourceResult } from "@/lib/useResource";

/**
 * Authn Platform — Shared organization list
 * File: apps/web-account/src/components/OrganizationsProvider.tsx
 *
 * One copy of `GET /v1/client/organizations` for the whole account section.
 *
 * Two things read it and they have to agree: the sidebar draws a row per workspace,
 * and the organizations page draws a card per workspace. Each fetching its own copy
 * gives two lists that drift — creating an organization on the page would fill in a
 * card the tree does not have, and leaving one would remove a card while its row
 * stayed behind, still linking to an anchor that no longer exists.
 *
 * `useOrganization` from the SDK cannot serve here: it keeps its state inside the
 * hook, so two components calling it hold two separate arrays. This is that state
 * lifted to the one place both of them are inside.
 */

interface OrganizationsValue {
  organizations: AuthnOrg[];
  /** True only until the first answer arrives; see {@link useResource}. */
  isLoading: boolean;
  isRefetching: boolean;
  error: AuthnError | null;
  refetch: () => Promise<void>;
}

/**
 * Undefined rather than a default value, so a consumer mounted outside the provider
 * fails loudly instead of rendering an account that appears to belong to no
 * workspaces.
 */
const OrganizationsContext = createContext<OrganizationsValue | undefined>(undefined);

export function OrganizationsProvider({ children }: { children: ReactNode }): ReactNode {
  const { client, isAuthenticated } = useAuth();

  const load = useCallback(async (): Promise<ResourceResult<AuthnOrg[]>> => {
    const result = await client.listOrganizations();
    return result.ok
      ? { ok: true, data: result.organizations }
      : { ok: false, error: result.error };
  }, [client]);

  // Held back until the session exists: the provider's refresh call settles after
  // the first render, and a request that goes out before it comes back 401.
  const orgs = useResource(load, { enabled: isAuthenticated });

  const value = useMemo<OrganizationsValue>(
    () => ({
      // An empty array while loading and after a failure, because every consumer
      // renders a list. `null` would make each of them repeat the same fallback.
      organizations: orgs.data ?? [],
      isLoading: orgs.isLoading,
      isRefetching: orgs.isRefetching,
      error: orgs.error,
      refetch: orgs.refetch,
    }),
    [orgs.data, orgs.error, orgs.isLoading, orgs.isRefetching, orgs.refetch],
  );

  return (
    <OrganizationsContext.Provider value={value}>{children}</OrganizationsContext.Provider>
  );
}

export function useOrganizations(): OrganizationsValue {
  const value = useContext(OrganizationsContext);
  if (!value) {
    throw new Error("useOrganizations must be used inside an OrganizationsProvider");
  }
  return value;
}
