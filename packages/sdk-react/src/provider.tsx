import React, { useEffect, useMemo, useRef, useState } from "react";
import { AuthnClient, AuthnError, AuthnErrorCode } from "@authn/js";
import type { AuthnSession, AuthnUser } from "@authn/js";
import { AuthnContext } from "./context";
import type { AuthnContextValue, AuthnProviderProps } from "./types";

export function AuthnProvider(props: AuthnProviderProps): React.JSX.Element {
  const { children, client: externalClient, publishableKey, ...configOptions } = props;

  // Defense-in-depth runtime guard for JS / un-typed consumers
  if (!externalClient && !publishableKey) {
    throw new AuthnError({
      message:
        "<AuthnProvider> requires either a `publishableKey` string or a pre-constructed `client` instance.",
      code: AuthnErrorCode.INVALID_CONFIG,
    });
  }

  // Ref to track if we own the client instance (and should destroy it on unmount)
  const isInternalClient = useRef(!externalClient);

  // Initialize client ONCE on mount
  const [client] = useState<AuthnClient>(() => {
    if (externalClient) {
      return externalClient;
    }
    return new AuthnClient({
      publishableKey: publishableKey!,
      ...configOptions,
    });
  });

  const [user, setUser] = useState<AuthnUser | null>(() => client.getUser());
  const [session, setSession] = useState<AuthnSession | null>(() =>
    client.getSession(),
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    // Subscribe to auth state changes
    const unsubscribe = client.onAuthStateChanged((nextUser, nextSession) => {
      setUser(nextUser);
      setSession(nextSession);
      setIsLoading(false);
    });

    return () => {
      unsubscribe();
      // Only destroy internal client instances created by this provider
      if (isInternalClient.current) {
        client.destroy();
      }
    };
  }, [client]);

  const contextValue = useMemo<AuthnContextValue>(
    () => ({
      client,
      user,
      session,
      isAuthenticated: user !== null && session !== null,
      isLoading,
    }),
    [client, user, session, isLoading],
  );

  return (
    <AuthnContext.Provider value={contextValue}>
      {children}
    </AuthnContext.Provider>
  );
}
