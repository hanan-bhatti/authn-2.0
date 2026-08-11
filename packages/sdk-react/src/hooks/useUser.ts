"use client";

import type { AuthnUser } from "@authn/js";
import { useAuthContext } from "../context";

/**
 * Access the active authenticated user, or `null` if unauthenticated.
 *
 * Convenience wrapper around `useAuth().user`.
 */
export function useUser(): AuthnUser | null {
  return useAuthContext().user;
}
