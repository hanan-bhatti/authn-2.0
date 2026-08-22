"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { AppConfig, AppConfigResult, AuthnClient, AuthnError } from "@authn/js";
import { useAuthContext } from "../context";

/**
 * inFlight holds one bootstrap request per client, so several components asking
 * for the configuration on the same render produce one round trip rather than
 * one each.
 *
 * A sign-up page realistically mounts this twice — once in the form, to learn the
 * password rules, and once in a wrapper, to apply the tenant's branding — and the
 * second component would otherwise render an empty configuration while a
 * duplicate request it did not need was in flight.
 *
 * Keyed weakly so a destroyed client takes its entry with it: holding the client
 * strongly here would keep every client a page ever built alive for the life of
 * the module.
 */
const inFlight = new WeakMap<AuthnClient, Promise<AppConfigResult>>();

function fetchOnce(client: AuthnClient): Promise<AppConfigResult> {
  const existing = inFlight.get(client);
  if (existing) return existing;

  const request = client.getAppConfig().then((result) => {
    // A refusal is not cached. The configuration is what the page renders
    // itself from, so a transient failure must stay retryable rather than
    // pinning every later mount to the same error.
    if (!result.ok) inFlight.delete(client);
    return result;
  });

  inFlight.set(client, request);
  return request;
}

export interface UseAppConfigReturn {
  /** The bootstrap document, or null until it arrives. */
  config: AppConfig | null;
  isLoading: boolean;
  error: AuthnError | null;
  /** Refetches, bypassing the cache. For a branding change made in another tab. */
  reload: () => Promise<void>;
}

/**
 * Read the configuration a sign-in or sign-up page renders itself from: the
 * tenant's branding, which methods to offer, and the password policy the form
 * must agree with.
 *
 * The fetch starts on mount. Render a skeleton while `config` is null rather than
 * a default form — a form built from assumed defaults offers methods the tenant
 * disabled, and then rearranges itself once the real answer lands.
 *
 * @example
 * ```tsx
 * const { config, isLoading } = useAppConfig();
 * if (isLoading || !config) return <FormSkeleton />;
 * return <SignUpForm rules={config.passwordRules} methods={config.signInMethods} />;
 * ```
 */
export function useAppConfig(): UseAppConfigReturn {
  const { client } = useAuthContext();
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<AuthnError | null>(null);

  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const load = useCallback(
    async (bypassCache: boolean) => {
      setIsLoading(true);
      setError(null);

      if (bypassCache) inFlight.delete(client);

      const result = await fetchOnce(client);
      if (!isMounted.current) return;

      if (result.ok) {
        setConfig(result.config);
      } else {
        setError(result.error);
      }
      setIsLoading(false);
    },
    [client],
  );

  useEffect(() => {
    void load(false);
  }, [load]);

  const reload = useCallback(() => load(true), [load]);

  return { config, isLoading, error, reload };
}
