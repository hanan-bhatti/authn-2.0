import { createContext, useContext } from "react";
import { AuthnError, AuthnErrorCode } from "@authn/js";
import type { AuthnContextValue } from "./types";

export const AuthnContext = createContext<AuthnContextValue | null>(null);

export function useAuthContext(): AuthnContextValue {
  const context = useContext(AuthnContext);
  if (!context) {
    throw new AuthnError({
      message:
        "Authn React hooks must be used within an <AuthnProvider>. Wrap your application root in <AuthnProvider publishableKey=\"...\">.",
      code: AuthnErrorCode.INVALID_CONFIG,
    });
  }
  return context;
}
