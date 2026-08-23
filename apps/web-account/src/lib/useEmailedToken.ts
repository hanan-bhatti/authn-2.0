"use client";

/**
 * Authn Platform — Redeeming a token that arrived in a URL
 * File: apps/web-account/src/lib/useEmailedToken.ts
 *
 * Both emailed-link landings — email verification and the passwordless magic
 * link — do the same thing with the token in their query string, and every part
 * of it is easy to get subtly wrong against a credential that works exactly
 * once. So it is written here, once.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "@authn/react";
import type { AuthnClient, AuthnError } from "@authn/js";

/**
 * Where a redemption has got to.
 *
 * `missing` is a separate state rather than a failure because nothing was
 * attempted: the link arrived without a token, which is a truncated URL rather
 * than a refused one, and telling the user their link expired would send them to
 * request another that would arrive just as truncated.
 */
export type RedemptionState =
  | { status: "missing" }
  | { status: "working" }
  | { status: "done" }
  | { status: "failed"; error: AuthnError };

export interface Redemption {
  state: RedemptionState;
  /**
   * Re-sends the same token.
   *
   * Worth offering only after a transport failure, where nothing reached the
   * engine and the token is therefore untouched. After a refusal the token is
   * spent and this would just collect the same answer.
   */
  retry: () => void;
}

/**
 * Redeems `token` once, automatically, and reports how it went.
 *
 * `redeem` receives the token and returns the SDK's discriminated result. It is
 * expected to call the provider's client, which is what the attempt is keyed on.
 */
export function useEmailedToken(
  token: string | undefined,
  redeem: (token: string) => Promise<{ ok: true } | { ok: false; error: AuthnError }>,
): Redemption {
  // Read here rather than taken as arguments so that no caller has to know the
  // client's identity matters. Getting that wrong costs the user their link.
  const { client, isLoading } = useAuth();

  const [state, setState] = useState<RedemptionState>(() =>
    token ? { status: "working" } : { status: "missing" },
  );

  // The callback is held in a ref instead of listed as a dependency. It closes
  // over the SDK client and is rebuilt every render, so depending on it would
  // restart the effect below — and a restart spends a single-use token.
  const redeemRef = useRef(redeem);
  redeemRef.current = redeem;

  // An attempt is identified by the client it was made on and by how many times
  // the page has asked for another. Everything that should cause a second
  // redemption changes one of the two, and nothing else can.
  const attemptedOn = useRef<AuthnClient | null>(null);
  const attemptedRetry = useRef(-1);
  const [retryCount, setRetryCount] = useState(0);

  const retry = useCallback(() => setRetryCount((count) => count + 1), []);

  useEffect(() => {
    if (!token) return;

    // Nothing is sent while the provider is still settling, and this is the guard
    // that matters most on this page.
    //
    // The provider destroys its client when this component unmounts and builds a
    // replacement when it mounts again, which strict mode makes it do on every
    // page load in development. A redemption started before that happens is
    // aborted halfway — and an abort is a client-side act, so whether the engine
    // had already accepted the token is a race the engine wins as soon as the CORS
    // preflight is warm. Losing it means the token is spent by a request whose
    // reply was thrown away, and the retry that follows is told, correctly, that
    // the link has already been used.
    //
    // Waiting until the provider reports itself settled means the doomed attempt
    // is never made at all. Child effects run before parent ones, so on the mount
    // this observes the provider has not yet cleared its initial isLoading.
    if (isLoading || client.isDestroyed()) return;

    if (attemptedOn.current === client && attemptedRetry.current === retryCount) return;
    attemptedOn.current = client;
    attemptedRetry.current = retryCount;

    setState({ status: "working" });

    void redeemRef.current(token).then((result) => {
      // No unmount guard. React no longer warns about setting state after
      // unmount, and a guard here would be actively wrong: strict mode's teardown
      // would trip it, the reply would be dropped, and the page would sit on
      // "working" forever in development.
      setState(result.ok ? { status: "done" } : { status: "failed", error: result.error });
    });
  }, [client, isLoading, token, retryCount]);

  useEffect(() => {
    if (!token) return;

    // The token is dropped from the address bar as soon as it has been read. It
    // is a credential, and while it is in the URL it is in the history entry the
    // back button returns to, in whatever the user copies out of the address bar,
    // and in the Referer sent to any third-party resource the page loads.
    //
    // replaceState rather than a router navigation: this edits the current history
    // entry in place instead of adding one, so Back leaves the app rather than
    // returning to a URL that still carries the token.
    const url = new URL(window.location.href);
    if (!url.searchParams.has("token")) return;
    url.searchParams.delete("token");
    window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
  }, [token]);

  // Retrying reads the token from props, not from the address bar — which the
  // effect above has already cleaned. Editing history does not re-render, so the
  // value the page was given is still here.
  return { state, retry };
}
