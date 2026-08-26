/**
 * @authn/react — Provider lifecycle
 *
 * The provider owns two things with different lifetimes: a subscription to the
 * client's auth state, and — when it built the client itself — the client. React
 * runs setup and cleanup more than once for a single mount, so anything torn down
 * in cleanup has to be re-established on the next setup. These tests hold the
 * provider to that.
 *
 * Note on the harness: `renderHook` does not reproduce the double invocation even
 * with StrictMode in its wrapper, so every case below renders a real tree. A test
 * written against `renderHook` would pass whether or not the provider survives a
 * remount, which is the one thing being checked here.
 */

import React, { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, waitFor, screen } from "@testing-library/react";
import { AuthnClient } from "@authn/js";
import { AuthnProvider, useAuth } from "../index";

const publishableKey = "pk_test_demo12345678901234567890123456789012";

/**
 * noSessionFetch answers the session probe the way a browser holding no refresh
 * cookie is answered: 401 from the token endpoint.
 *
 * Every case supplies its own fetch. The alternative is the global one, which
 * sends real requests to the configured endpoint — slow, dependent on the
 * network, and answered by whatever happens to be listening.
 */
function noSessionFetch(): ReturnType<typeof vi.fn> {
  return vi.fn(
    async () =>
      new Response(JSON.stringify({ error: { code: "invalid_token" } }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
  );
}

/**
 * callsTo counts the requests a mock received for one path.
 *
 * Needed because more than one request stream shares a mock: the provider's
 * session probe runs on mount whatever else a case does, and after teardown the
 * two streams are supposed to behave differently.
 */
function callsTo(fetchMock: ReturnType<typeof vi.fn>, path: string): number {
  return fetchMock.mock.calls.filter(([url]) => String(url).includes(path))
    .length;
}

/**
 * Consumer surfaces the context so assertions can read it, and records the
 * client instance for checks that outlive the render.
 */
let observed: AuthnClient | null = null;

function Consumer(): React.JSX.Element {
  const { isLoading, isAuthenticated, client } = useAuth();
  observed = client;
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="authed">{String(isAuthenticated)}</span>
    </div>
  );
}

// Unhandled rejections are the symptom the provider used to produce, and they do
// not fail a vitest run on their own — a promise nobody catches is invisible
// unless something is listening. So the listener is the assertion.
let rejections: string[] = [];
const recordRejection = (reason: unknown): void => {
  const err = reason as { code?: string; message?: string };
  rejections.push(String(err?.code ?? err?.message ?? reason));
};

beforeEach(() => {
  observed = null;
  rejections = [];
  process.on("unhandledRejection", recordRejection);
});

afterEach(() => {
  process.off("unhandledRejection", recordRejection);
});

describe("<AuthnProvider> lifecycle", () => {
  // In development React mounts, tears down and remounts every effect to surface
  // cleanup that cannot be undone. The provider's cleanup destroys the client it
  // built, and the client survives that cycle in state — so the second setup is
  // handed a client that refuses every call, including the session probe.
  //
  // Next.js enables StrictMode by default, which makes this the ordinary path for
  // anyone developing against the SDK, not an edge case.
  it("leaves a usable client after the double mount React performs in development", async () => {
    const fetchMock = noSessionFetch();

    render(
      <StrictMode>
        <AuthnProvider publishableKey={publishableKey} fetch={fetchMock}>
          <Consumer />
        </AuthnProvider>
      </StrictMode>,
    );

    await waitFor(() =>
      expect(screen.getByTestId("loading").textContent).toBe("false"),
    );

    // Two probes, one per live client. The count is what proves the second setup
    // ran against a client that could still reach the network: one probe means it
    // was handed a destroyed client and got nowhere.
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    expect(observed).not.toBeNull();
    expect(observed!.isDestroyed()).toBe(false);
    expect(screen.getByTestId("authed").textContent).toBe("false");

    // The client handed to consumers has to still work — a provider that reports
    // settled while holding a dead one has only moved the failure to the first
    // call a component makes.
    //
    // Wrapped because the tree is still mounted: the call notifies the provider's
    // auth-state subscriber, and those updates belong inside act() like any other
    // state change a test causes.
    await act(async () => {
      await expect(observed!.refreshSession()).resolves.toMatchObject({
        ok: false,
      });
    });

    expect(rejections, "the mount-time probe must not reject unhandled").toEqual(
      [],
    );
  });

  // A probe is in flight when a fast navigation unmounts the provider. Its
  // completion must not reach the unmounted tree — and, because the probe is a
  // refresh-token rotation, it must not be cancelled either.
  //
  // The probe posts to the token endpoint, which spends the presented refresh
  // token and returns its replacement in a Set-Cookie. A network failure there is
  // ambiguous: the request may have arrived and had its reply lost, in which case
  // the browser is now holding a token the engine has already retired and only a
  // retry can recover a working one. So the chain deliberately outlives the
  // client, unlike an ordinary request's. Its backoff — 1s, then 2s, then 4s — is
  // bounded by the engine's ten-second rotation grace window, which is what makes
  // a late retry a recovery rather than a replay.
  it("lets an in-flight session probe retry after the provider unmounts", async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });

    const { unmount } = render(
      <AuthnProvider publishableKey={publishableKey} fetch={fetchMock}>
        <Consumer />
      </AuthnProvider>,
    );

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const client = observed!;
    unmount();

    expect(client.isDestroyed()).toBe(true);

    // The first retry is a second out. Waiting past it is the only way to tell a
    // chain that continued from one that simply had not got round to retrying.
    await new Promise((resolve) => setTimeout(resolve, 1300));
    expect(
      fetchMock,
      "the rotation's retry chain must survive teardown",
    ).toHaveBeenCalledTimes(2);

    expect(
      rejections,
      "a probe retrying past teardown must not reject unhandled",
    ).toEqual([]);
  }, 10_000);

  // The exemption is the rotation's alone. Every other request an abandoned
  // provider left in flight has to stop, retry chain included: a network failure
  // is retried three times with backoff, so an abandoned read otherwise keeps
  // issuing requests for seconds on behalf of a tree that is gone.
  it("cancels an in-flight read when the provider unmounts", async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });

    render(
      <AuthnProvider publishableKey={publishableKey} fetch={fetchMock}>
        <Consumer />
      </AuthnProvider>,
    );

    await waitFor(() => expect(observed).not.toBeNull());
    const client = observed!;

    const read = client.getProfile();
    // Counted by path. The provider's own session probe is failing and retrying on
    // the same mock, and its chain is the one that is meant to continue, so a bare
    // call count cannot tell the two streams apart.
    await waitFor(() => expect(callsTo(fetchMock, "/profile")).toBeGreaterThan(0));
    const beforeTeardown = callsTo(fetchMock, "/profile");

    client.destroy();
    await expect(read).resolves.toMatchObject({ ok: false });

    await new Promise((resolve) => setTimeout(resolve, 1300));
    expect(
      callsTo(fetchMock, "/profile"),
      "the read's retry chain outlived the client it belonged to",
    ).toBe(beforeTeardown);
  }, 10_000);

  // An externally supplied client belongs to the caller, who may be holding it
  // for a route they navigate back to. Destroying it here would break that caller
  // from code they cannot see.
  it("does not destroy a client it did not create", async () => {
    const fetchMock = noSessionFetch();
    const client = new AuthnClient({ publishableKey, fetch: fetchMock });

    const { unmount } = render(
      <StrictMode>
        <AuthnProvider client={client}>
          <Consumer />
        </AuthnProvider>
      </StrictMode>,
    );

    await waitFor(() =>
      expect(screen.getByTestId("loading").textContent).toBe("false"),
    );
    unmount();

    expect(client.isDestroyed()).toBe(false);
    client.destroy();
  });

  // The caller swapped in a different client. Continuing with the first one would
  // send requests through a configuration the consumer has already replaced.
  it("adopts a client supplied later in place of the original", async () => {
    const firstFetch = noSessionFetch();
    const secondFetch = noSessionFetch();
    const first = new AuthnClient({ publishableKey, fetch: firstFetch });
    const second = new AuthnClient({ publishableKey, fetch: secondFetch });

    const { rerender } = render(
      <AuthnProvider client={first}>
        <Consumer />
      </AuthnProvider>,
    );
    await waitFor(() => expect(observed).toBe(first));

    rerender(
      <AuthnProvider client={second}>
        <Consumer />
      </AuthnProvider>,
    );
    await waitFor(() => expect(observed).toBe(second));

    expect(first.isDestroyed()).toBe(false);
    expect(second.isDestroyed()).toBe(false);
    first.destroy();
    second.destroy();
  });
});
