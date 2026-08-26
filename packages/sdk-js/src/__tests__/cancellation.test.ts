/**
 * @authn/js — Request cancellation
 *
 * A request can end without an answer for two unrelated reasons: the server took
 * too long, or the caller went away. They arrive at the fetch layer as the same
 * AbortError, and telling them apart is what these tests hold the client to — a
 * timeout is retryable and a cancellation is not, so conflating them means an
 * abandoned request gets tried again on behalf of a caller that no longer exists.
 */

import { describe, expect, it, vi } from "vitest";
import { HttpClient } from "../core/http";
import { AuthnClient } from "../client";
import { AuthnError, AuthnErrorCode } from "../types";
import { callHeaders } from "./helpers";

const publishableKey = "pk_test_demo12345678901234567890123456789012";

/** INITIAL_BACKOFF_MS mirrors the client's first retry delay. */
const INITIAL_BACKOFF_MS = 1000;

/** silentLogger keeps the retry warnings out of the test output. */
const silentLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

/** jsonOk answers with a 200 and an empty JSON body. */
function jsonOk(): Response {
  return new Response("{}", {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * hangingFetch never settles on its own, and rejects the way a real fetch does
 * when its signal is aborted.
 *
 * Emulating that rejection is the whole point: the client's behaviour depends on
 * receiving a DOMException named AbortError, so a stub that merely resolved late
 * would exercise a path production never takes.
 */
function hangingFetch(): ReturnType<typeof vi.fn> {
  return vi.fn(
    (_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      }),
  );
}

function httpClient(
  fetchFn: unknown,
  overrides: Partial<{ timeout: number; lifetimeSignal: AbortSignal }> = {},
): HttpClient {
  return new HttpClient({
    baseUrl: "http://localhost:8080",
    apiKey: publishableKey,
    timeout: overrides.timeout ?? 10_000,
    logger: silentLogger,
    customFetch: fetchFn as typeof globalThis.fetch,
    lifetimeSignal: overrides.lifetimeSignal,
  });
}

describe("HttpClient cancellation", () => {
  it("refuses a request on an already-cancelled lifetime without touching the network", async () => {
    const fetchMock = vi.fn(async () => jsonOk());
    const lifetime = new AbortController();
    lifetime.abort();

    const http = httpClient(fetchMock, { lifetimeSignal: lifetime.signal });

    await expect(http.get("/v1/whoami")).rejects.toMatchObject({
      code: AuthnErrorCode.CANCELLED,
    });
    expect(
      fetchMock,
      "a destroyed client must not open a connection",
    ).not.toHaveBeenCalled();
  });

  it("reports a cancelled in-flight request as cancelled, not as a timeout", async () => {
    const fetchMock = hangingFetch();
    const lifetime = new AbortController();
    const http = httpClient(fetchMock, {
      lifetimeSignal: lifetime.signal,
      timeout: 10_000,
    });

    const inFlight = http.get("/v1/whoami");
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    lifetime.abort();

    const err = (await inFlight.catch((e: unknown) => e)) as AuthnError;
    expect(err.code).toBe(AuthnErrorCode.CANCELLED);
    // The distinction is not cosmetic: a caller retrying on isRetryable would
    // keep a destroyed client making requests.
    expect(err.isRetryable).toBe(false);
  });

  it("still reports a genuine timeout as a timeout", async () => {
    const fetchMock = hangingFetch();
    const lifetime = new AbortController();
    const http = httpClient(fetchMock, {
      lifetimeSignal: lifetime.signal,
      timeout: 30,
    });

    const err = (await http.get("/v1/whoami").catch((e: unknown) => e)) as AuthnError;
    expect(err.code).toBe(AuthnErrorCode.TIMEOUT);
    expect(err.isRetryable).toBe(true);
  });

  it("abandons the retry chain when the lifetime ends mid-backoff", async () => {
    // A network failure is retried three times with exponential backoff, so an
    // uncancelled chain keeps issuing requests for seconds after teardown.
    const fetchMock = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    const lifetime = new AbortController();
    const http = httpClient(fetchMock, { lifetimeSignal: lifetime.signal });

    const inFlight = http.get("/v1/whoami");
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const abortedAt = Date.now();
    lifetime.abort();

    await expect(inFlight).rejects.toMatchObject({
      code: AuthnErrorCode.CANCELLED,
    });

    // Promptly, not after the backoff has run its course. A timer left to expire
    // holds the event loop open for as much as several seconds past teardown —
    // long enough to keep a serverless invocation from freezing and to leave a
    // test runner waiting on work nobody is expecting an answer from.
    expect(Date.now() - abortedAt).toBeLessThan(INITIAL_BACKOFF_MS);

    // Past the first backoff, which is where a second attempt would have landed.
    await new Promise((resolve) => setTimeout(resolve, 1300));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  }, 10_000);

  it("carries per-request headers into a retried attempt", async () => {
    // A retry that drops them silently changes the request: these headers carry
    // things like a step-up MFA token, so the second attempt would be a different
    // — and unauthorized — request from the first.
    let call = 0;
    const fetchMock = vi.fn(async () => {
      call += 1;
      if (call === 1) {
        return new Response("{}", {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "0" },
        });
      }
      return jsonOk();
    });

    const http = httpClient(fetchMock);
    await http.post("/v1/mfa/verify", { code: "000000" }, { "X-Authn-MFA-Token": "mfa_abc" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(callHeaders(fetchMock, 1)["X-Authn-MFA-Token"]).toBe("mfa_abc");
  }, 10_000);
});

describe("AuthnClient teardown", () => {
  it("reports whether it has been destroyed", () => {
    const client = new AuthnClient({ publishableKey });
    expect(client.isDestroyed()).toBe(false);
    client.destroy();
    expect(client.isDestroyed()).toBe(true);
  });

  it("tolerates being destroyed more than once", () => {
    const client = new AuthnClient({ publishableKey });
    client.destroy();
    expect(() => client.destroy()).not.toThrow();
  });

  it("cancels a request already in flight", async () => {
    const fetchMock = hangingFetch();
    const client = new AuthnClient({
      publishableKey,
      fetch: fetchMock as unknown as typeof globalThis.fetch,
    });

    const inFlight = client.getProfile();
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    client.destroy();

    // The SDK's methods convert every failure into a result rather than throwing,
    // so the cancellation surfaces here as a reported error.
    const result = await inFlight;
    expect(result.ok).toBe(false);
  });

  it("lets a refresh already in flight finish", async () => {
    // The one request teardown must not cut short. The engine spends the presented
    // refresh token and returns its replacement as a Set-Cookie on this reply, so a
    // cancelled rotation leaves the browser holding a token the engine has retired
    // — and the next ordinary use of a retired token is reuse, which revokes every
    // session on the account. React's development double-mount reaches this exact
    // path: mount, destroy, remount.
    let release: ((response: Response) => void) | undefined;
    let aborted = false;
    const fetchMock = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((resolve, reject) => {
          release = resolve;
          init?.signal?.addEventListener("abort", () => {
            aborted = true;
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        }),
    );

    const client = new AuthnClient({
      publishableKey,
      fetch: fetchMock as unknown as typeof globalThis.fetch,
    });

    const inFlight = client.refreshSession();
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    client.destroy();

    expect(aborted).toBe(false);

    release!(
      new Response(
        JSON.stringify({
          user: {
            id: "usr_123",
            email: "test@example.com",
            email_verified: true,
            status: "active",
            created_at: "2026-08-01T00:00:00Z",
          },
          access_token: "jwt_rotated",
          expires_at: Math.floor(Date.now() / 1000) + 900,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const result = await inFlight;
    expect(result.ok).toBe(true);
    // The rotation landed, so the cookie is current. The session is not adopted:
    // the client is destroyed, and adopting it would schedule the next refresh on
    // a client whose caller is gone.
    expect(client.getSession()).toBeNull();
  });
});

describe("AuthnError.cancelled", () => {
  it("is never retryable", () => {
    expect(AuthnError.cancelled("/v1/whoami").isRetryable).toBe(false);
    expect(AuthnError.cancelled("/v1/whoami").code).toBe(AuthnErrorCode.CANCELLED);
  });
});
