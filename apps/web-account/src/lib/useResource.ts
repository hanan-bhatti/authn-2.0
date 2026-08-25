"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { AuthnError } from "@authn/js";

/**
 * Authn Platform — Reading a resource from the engine
 * File: apps/web-account/src/lib/useResource.ts
 *
 * Every account page is the same shape: ask the engine for something, show a
 * skeleton until it answers, show what it said, and re-ask after a change. This
 * is that shape once, so seven pages do not each invent their own idea of what
 * "loading" means.
 */

/**
 * What a loader hands back.
 *
 * The SDK answers `{ ok: false, error }` rather than throwing, so a loader is a
 * function that resolves either way and never rejects. Callers adapt the SDK's
 * per-method payload key into `data` at the call site, which keeps this hook from
 * needing to know that a profile arrives under `profile` and sessions under
 * `sessions`.
 */
export type ResourceResult<T> = { ok: true; data: T } | { ok: false; error: AuthnError };

export interface ResourceState<T> {
  data: T | null;
  error: AuthnError | null;
  /**
   * True only until the first answer arrives.
   *
   * Separate from `isRefetching` because they call for different treatment: the
   * first load has nothing to show and wants a skeleton, while a reload after a
   * save has the previous value on screen and wants it left alone. Collapsing the
   * two makes every successful save blink the whole card back to grey, which
   * reads as the page having lost the thing the user just changed.
   */
  isLoading: boolean;
  /** True while a reload runs behind data that is already on screen. */
  isRefetching: boolean;
  refetch: () => Promise<void>;
  /**
   * Writes a value locally without asking the engine again.
   *
   * For a mutation whose response already contains the updated resource: the
   * answer is in hand, and spending a round trip to fetch what was just returned
   * shows the user a stale value for the length of that trip.
   */
  mutate: (next: T) => void;
}

export interface UseResourceOptions {
  /**
   * Holds the request back until the caller is ready.
   *
   * The session is established by a refresh call the provider makes on mount, so
   * a request fired on the first render goes out unauthenticated and comes back
   * 401 — which would render as "could not load" on a page that is merely early.
   */
  enabled?: boolean;
}

export function useResource<T>(
  load: () => Promise<ResourceResult<T>>,
  options: UseResourceOptions = {},
): ResourceState<T> {
  const { enabled = true } = options;

  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<AuthnError | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(enabled);
  const [isRefetching, setIsRefetching] = useState<boolean>(false);

  // Counts requests so a slow one that has been superseded cannot write over the
  // newer answer. Without it, a refetch triggered twice in quick succession
  // settles in whatever order the network happens to return.
  const generation = useRef(0);
  const mounted = useRef(true);
  const settledOnce = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async () => {
    const mine = ++generation.current;

    if (settledOnce.current) setIsRefetching(true);
    else setIsLoading(true);

    const result = await load();

    if (!mounted.current || mine !== generation.current) return;

    if (result.ok) {
      setData(result.data);
      setError(null);
    } else {
      setError(result.error);
    }

    settledOnce.current = true;
    setIsLoading(false);
    setIsRefetching(false);
  }, [load]);

  useEffect(() => {
    if (!enabled) return;
    void run();
  }, [enabled, run]);

  const mutate = useCallback((next: T) => {
    // Bumped so a request already in flight cannot land on top of the value the
    // caller just wrote from a mutation response.
    generation.current += 1;
    settledOnce.current = true;
    setData(next);
    setError(null);
  }, []);

  return { data, error, isLoading, isRefetching, refetch: run, mutate };
}
