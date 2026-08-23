import { describe, expect, it, vi } from "vitest";
import { AuthnClient } from "../client";
import { AuthnErrorCode } from "../types";
import { callBody, callHeaders, callInit, callUrl, nth } from "./helpers";

const PK = "pk_test_demo12345678901234567890123456789012";

/** Build a mock fetch returning a single JSON payload. */
function mockJson(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    text: async () => JSON.stringify(body),
  });
}

/**
 * Build an authenticated client. The first fetch call logs in so that
 * subsequent calls carry an `Authorization` header, matching how session
 * endpoints are actually reached.
 */
async function authenticatedClient(mockFetch: ReturnType<typeof vi.fn>) {
  const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });

  mockFetch.mockResolvedValueOnce({
    ok: true,
    status: 200,
    headers: new Headers(),
    text: async () =>
      JSON.stringify({
        user: {
          id: "usr_sessions_owner",
          email: "owner@example.com",
          email_verified: true,
          status: "active",
          created_at: "2026-08-01T00:00:00Z",
        },
        access_token: "jwt_access_token",
        expires_at: Math.floor(Date.now() / 1000) + 900,
      }),
  });

  await client.login({ email: "owner@example.com", password: "SuperSecret123!" });
  return client;
}

const SESSION_FIXTURE = {
  id: "ses_current_abc",
  device: {
    browser: "Chrome 127",
    os: "macOS",
    device: "Desktop",
    label: "Chrome 127 on macOS",
  },
  ip_address: "203.0.113.10",
  location: "Berlin, DE",
  last_active_at: "2026-08-07T10:15:00Z",
  created_at: "2026-08-01T09:00:00Z",
  is_current: true,
};

const OTHER_SESSION_FIXTURE = {
  id: "ses_phone_xyz",
  device: {
    browser: "Safari 18",
    os: "iOS",
    device: "Mobile",
    label: "Safari 18 on iOS",
  },
  ip_address: "198.51.100.7",
  location: "",
  created_at: "2026-08-05T12:00:00Z",
  is_current: false,
};

describe("AuthnClient — listSessions()", () => {
  it("maps the server session list into camelCase device sessions", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({ sessions: [SESSION_FIXTURE, OTHER_SESSION_FIXTURE] }),
    });

    const result = await client.listSessions();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.sessions).toHaveLength(2);

      const current = nth(result.sessions, 0);
      const phone = nth(result.sessions, 1);
      expect(current.id).toBe("ses_current_abc");
      expect(current.isCurrent).toBe(true);
      expect(current.ipAddress).toBe("203.0.113.10");
      expect(current.location).toBe("Berlin, DE");
      expect(current.lastActiveAt).toBe("2026-08-07T10:15:00Z");
      expect(current.createdAt).toBe("2026-08-01T09:00:00Z");
      expect(current.device.label).toBe("Chrome 127 on macOS");
      expect(current.device.browser).toBe("Chrome 127");
      expect(current.device.os).toBe("macOS");
      expect(current.device.device).toBe("Desktop");

      expect(phone.isCurrent).toBe(false);
      // `last_active_at` is omitempty server-side — must stay undefined, not null.
      expect(phone.lastActiveAt).toBeUndefined();
      expect(phone.location).toBe("");
    }
  });

  it("issues a GET to /v1/client/sessions with the bearer token attached", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ sessions: [] }),
    });

    await client.listSessions();

    const url = callUrl(mockFetch, 1);
    const init = callInit(mockFetch, 1);
    const headers = callHeaders(mockFetch, 1);
    expect(url).toContain("/v1/client/sessions");
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("include");
    expect(headers["Authorization"]).toBe("Bearer jwt_access_token");
    expect(headers["X-Authn-Publishable-Key"]).toBe(PK);
  });

  it("returns an empty array when the server omits the sessions key", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({}),
    });

    const result = await client.listSessions();

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.sessions).toEqual([]);
  });

  it("surfaces a 401 as an auth error without throwing", async () => {
    const mockFetch = mockJson(
      { error: "session authentication required: missing or invalid access token" },
      401,
    );

    const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });
    const result = await client.listSessions();

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.statusCode).toBe(401);
      expect(result.error.code).toBe(AuthnErrorCode.UNAUTHORIZED);
    }
  });
});

describe("AuthnClient — revokeSession()", () => {
  it("posts the session_id and reports a count of 1", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({ message: "session revoked", session_id: "ses_phone_xyz" }),
    });

    const result = await client.revokeSession("ses_phone_xyz");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.count).toBe(1);
      expect(result.message).toBe("session revoked");
    }

    const url = callUrl(mockFetch, 1);
    const init = callInit(mockFetch, 1);
    expect(url).toContain("/v1/client/sessions/revoke");
    expect(init.method).toBe("POST");
    expect(callBody(mockFetch, 1)).toEqual({ session_id: "ses_phone_xyz" });
  });

  it("returns a validation error for an empty session id without making a request", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    const callsBefore = mockFetch.mock.calls.length;

    const result = await client.revokeSession("");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(AuthnErrorCode.INVALID_PARAMS);
      expect(result.error.details).toEqual({ field: "sessionId" });
    }
    // No network call should have been made.
    expect(mockFetch.mock.calls.length).toBe(callsBefore);
  });

  it("surfaces a 403 when the session belongs to another user", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({ error: "unauthorized: session does not belong to user" }),
    });

    const result = await client.revokeSession("ses_someone_else");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.statusCode).toBe(403);
  });

  it("surfaces a 404 for an unknown session", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      headers: new Headers(),
      text: async () => JSON.stringify({ error: "session not found" }),
    });

    const result = await client.revokeSession("ses_missing");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.statusCode).toBe(404);
  });
});

describe("AuthnClient — revokeOtherSessions()", () => {
  it("returns the server-reported count and leaves the local session intact", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({ message: "all other sessions revoked", count: 3 }),
    });

    const result = await client.revokeOtherSessions();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.count).toBe(3);
      expect(result.message).toBe("all other sessions revoked");
    }

    // This device stays signed in.
    expect(client.isAuthenticated()).toBe(true);
    expect(client.getToken()).toBe("jwt_access_token");

    const url = callUrl(mockFetch, 1);
    const init = callInit(mockFetch, 1);
    expect(url).toContain("/v1/client/sessions/revoke-others");
    expect(init.method).toBe("POST");
  });

  it("defaults count to 0 when the server omits it", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ message: "all other sessions revoked" }),
    });

    const result = await client.revokeOtherSessions();
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.count).toBe(0);
  });

  it("surfaces a 401 as an auth error", async () => {
    const mockFetch = mockJson({ error: "session authentication required" }, 401);
    const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });

    const result = await client.revokeOtherSessions();

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe(AuthnErrorCode.UNAUTHORIZED);
  });
});

describe("AuthnClient — revokeAllSessions()", () => {
  it("clears the local session because this client's tokens are now invalid", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    expect(client.isAuthenticated()).toBe(true);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ message: "all sessions revoked", count: 4 }),
    });

    const result = await client.revokeAllSessions();

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.count).toBe(4);

    expect(client.isAuthenticated()).toBe(false);
    expect(client.getSession()).toBeNull();
    expect(client.getUser()).toBeNull();
    expect(client.getToken()).toBeNull();
  });

  it("notifies auth state listeners with null", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    const listener = vi.fn();
    client.onAuthStateChanged(listener);
    listener.mockClear();

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ message: "all sessions revoked", count: 1 }),
    });

    await client.revokeAllSessions();

    expect(listener).toHaveBeenCalledWith(null, null);
  });

  it("keeps the local session when the server rejects the request", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      headers: new Headers(),
      text: async () => JSON.stringify({ error: "database unavailable" }),
    });

    const result = await client.revokeAllSessions();

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe(AuthnErrorCode.SERVER_ERROR);
    // Revocation failed, so the session must not be cleared locally.
    expect(client.isAuthenticated()).toBe(true);
  });
});

describe("AuthnClient — session methods after destroy()", () => {
  it("throws on every session method once the client is destroyed", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    client.destroy();

    await expect(client.listSessions()).rejects.toThrow();
    await expect(client.revokeSession("ses_x")).rejects.toThrow();
    await expect(client.revokeOtherSessions()).rejects.toThrow();
    await expect(client.revokeAllSessions()).rejects.toThrow();
  });
});
