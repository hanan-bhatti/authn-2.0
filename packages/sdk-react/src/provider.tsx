"use client";

import React, { useEffect, useMemo, useState } from "react";
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

  // A client supplied as a prop belongs to the caller, who may be holding it for
  // a route they navigate back to; only one this provider built is ours to
  // destroy. Derived from the current prop rather than latched on first render,
  // so a consumer that switches between the two modes is handled.
  const ownsClient = externalClient === undefined;

  function buildClient(): AuthnClient {
    if (externalClient) return externalClient;
    return new AuthnClient({
      publishableKey: publishableKey!,
      ...configOptions,
    });
  }

  const [client, setClient] = useState<AuthnClient>(buildClient);
  const [user, setUser] = useState<AuthnUser | null>(() => client.getUser());
  const [session, setSession] = useState<AuthnSession | null>(() =>
    client.getSession(),
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Adopt a client the caller swapped in. Without this the first one supplied
  // would be used for the life of the provider, silently ignoring the new one.
  if (externalClient && externalClient !== client) {
    setClient(externalClient);
    setUser(externalClient.getUser());
    setSession(externalClient.getSession());
  }

  useEffect(() => {
    // React runs cleanup and setup again for the same mount in development, and
    // state survives that cycle — so setup can be handed the very client its own
    // cleanup destroyed. Replacing it is what makes the pair symmetric: the
    // state change re-runs this effect against a live client. Leaving it in
    // place instead would hand consumers a client that throws on every call.
    if (client.isDestroyed()) {
      if (!ownsClient) {
        // The caller destroyed their own client. Nothing here can revive it, and
        // rebuilding is not this provider's call, so it reports settled rather
        // than waiting on a probe that cannot run.
        setIsLoading(false);
        return;
      }
      const replacement = buildClient();
      setClient(replacement);
      setUser(replacement.getUser());
      setSession(replacement.getSession());
      return;
    }

    // Set once by cleanup, so a probe that completes after teardown does not
    // write to a component that is no longer mounted.
    let active = true;

    const unsubscribe = client.onAuthStateChanged((nextUser, nextSession) => {
      setUser(nextUser);
      setSession(nextSession);
      setIsLoading(false);
    });

    if (!client.getSession()) {
      setIsLoading(true);
      client
        .refreshSession()
        .catch(() => {
          // refreshSession answers ordinary failures with `{ ok: false }`; the
          // only rejection it produces is a destroyed client, which means this
          // probe was abandoned deliberately and there is nothing to report.
        })
        .finally(() => {
          if (active) setIsLoading(false);
        });
    } else {
      setIsLoading(false);
    }

    return () => {
      active = false;
      unsubscribe();
      if (ownsClient) {
        client.destroy();
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, ownsClient]);

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
