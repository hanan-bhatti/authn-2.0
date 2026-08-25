"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { AuthnError, UsernameUnavailableReason } from "@authn/js";
import { checkUsernameFormat } from "@authn/js";
import { useAuthContext } from "../context";

/**
 * Where a handle stands right now.
 *
 * `invalid` is answered without a request — the shape rules are shared with the
 * engine, so a handle that breaks one can be refused locally. `unavailable`
 * always came from the server, and is the only state that can carry suggestions.
 */
export type UsernameStatus =
  | "idle"
  | "invalid"
  | "checking"
  | "available"
  | "unavailable"
  | "error";

export interface UseUsernameAvailabilityReturn {
  status: UsernameStatus;
  /** Sentence to show under the field, or null when there is nothing to say. */
  message: string | null;
  suggestions: string[];
  /** Set only when `status` is `unavailable`, distinguishing taken from reserved. */
  reason: UsernameUnavailableReason | null;
  /** The form the handle will be stored as, once the shape is valid. */
  canonical: string | null;
  error: AuthnError | null;
  reset: () => void;
}

export interface UseUsernameAvailabilityOptions {
  /** Feeds the suggestion generator; never stored. */
  name?: string;
  /**
   * How long to wait after the last keystroke. The default is tuned to the
   * endpoint's budget of 60 requests a minute: a fast typist correcting a handle
   * produces a burst, and firing per keystroke would spend that budget inside a
   * single word and make the field look broken.
   */
  debounceMs?: number;
  /** Set false to hold every request — while another field has focus, say. */
  enabled?: boolean;
}

const DEFAULT_DEBOUNCE_MS = 400;

/**
 * Track whether a username can be registered as it is typed.
 *
 * Shape problems appear immediately; only the questions that need the server —
 * taken, reserved, and the suggestions — are debounced. Nothing is reserved by
 * asking: a handle reported free can be claimed a moment later, so sign-up still
 * has to handle a 409 and this hook is guidance rather than a verdict.
 *
 * @example
 * ```tsx
 * const handle = useUsernameAvailability(username, { name });
 * // handle.status === "unavailable" && handle.suggestions.length > 0
 * ```
 */
export function useUsernameAvailability(
  username: string,
  options: UseUsernameAvailabilityOptions = {},
): UseUsernameAvailabilityReturn {
  const { client } = useAuthContext();
  const { name, debounceMs = DEFAULT_DEBOUNCE_MS, enabled = true } = options;

  const [status, setStatus] = useState<UsernameStatus>("idle");
  const [message, setMessage] = useState<string | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [reason, setReason] = useState<UsernameUnavailableReason | null>(null);
  const [error, setError] = useState<AuthnError | null>(null);

  // Every probe carries the generation it was started in, and a reply from an
  // older one is dropped. Without this, typing "alex" then "alexsmith" shows
  // whichever request finished last rather than the answer to what is on screen —
  // and the wrong one of those is a green tick under a taken handle.
  const generation = useRef(0);

  const reset = useCallback(() => {
    generation.current += 1;
    setStatus("idle");
    setMessage(null);
    setSuggestions([]);
    setReason(null);
    setError(null);
  }, []);

  const trimmed = username.trim();
  const format = checkUsernameFormat(trimmed);
  const canonical = format.canonical ?? null;

  useEffect(() => {
    const current = ++generation.current;
    const settled = () => current === generation.current;

    if (!enabled || trimmed === "") {
      setStatus("idle");
      setMessage(null);
      setSuggestions([]);
      setReason(null);
      setError(null);
      return;
    }

    if (!format.valid) {
      setStatus("invalid");
      setMessage(format.message ?? null);
      setSuggestions([]);
      setReason("invalid");
      setError(null);
      return;
    }

    setStatus("checking");
    setMessage(null);
    setError(null);

    const timer = setTimeout(() => {
      void (async () => {
        const result = await client.checkUsername({ username: trimmed, name });
        if (!settled()) return;

        if (!result.ok) {
          // A failed probe is not an unavailable handle. Reporting it as one
          // would block a sign-up over a network blip, so the field is left
          // usable and the server decides on submit.
          setStatus("error");
          setMessage(null);
          setSuggestions([]);
          setReason(null);
          setError(result.error);
          return;
        }

        const { available, message: serverMessage, suggestions: alternatives, reason: serverReason } =
          result.availability;
        setStatus(available ? "available" : "unavailable");
        setMessage(available ? null : (serverMessage ?? null));
        setSuggestions(alternatives ?? []);
        setReason(available ? null : (serverReason ?? null));
        setError(null);
      })();
    }, debounceMs);

    return () => clearTimeout(timer);
  }, [client, trimmed, name, debounceMs, enabled, format.valid, format.message]);

  return { status, message, suggestions, reason, canonical, error, reset };
}
