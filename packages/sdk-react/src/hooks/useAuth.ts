"use client";

import { useAuthContext } from "../context";
import type { UseAuthReturn } from "../types";

/**
 * Access the current authentication state and core AuthnClient instance.
 *
 * Must be used inside `<AuthnProvider>`.
 */
export function useAuth(): UseAuthReturn {
  return useAuthContext();
}
