import React from "react";
import { describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { AuthnClient } from "@authn/js";
import { AuthnProvider, usePasskeys, useTOTP } from "../index";

/**
 * offlineFetch answers every request the way a browser holding no refresh cookie
 * is answered: 401 from the token endpoint.
 *
 * Spying on the method under test is not enough — the provider probes for an
 * existing session on mount, so a client left with the global fetch sends a real
 * request to the configured endpoint, and the suite becomes slow, network-dependent,
 * and answered by whatever happens to be listening.
 */
function offlineFetch(): typeof globalThis.fetch {
  return vi.fn(
    async () =>
      new Response(JSON.stringify({ error: { code: "invalid_token" } }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
  ) as unknown as typeof globalThis.fetch;
}

describe("useTOTP and usePasskeys Hooks", () => {
  const validPk = "pk_test_demo12345678901234567890123456789012";

  const createWrapper = () => {
    const client = new AuthnClient({ publishableKey: validPk, fetch: offlineFetch() });
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <AuthnProvider client={client}>{children}</AuthnProvider>
    );
    return { client, wrapper };
  };

  it("should throw error if useTOTP or usePasskeys are used outside provider", () => {
    expect(() => renderHook(() => useTOTP())).toThrow("must be used within an <AuthnProvider>");
    expect(() => renderHook(() => usePasskeys())).toThrow("must be used within an <AuthnProvider>");
  });

  it("useTOTP calls client.enrollTOTP and updates loading/error state", async () => {
    const { client, wrapper } = createWrapper();
    vi.spyOn(client, "enrollTOTP").mockResolvedValue({
      ok: true,
      secret: "JBSWY3DPEHPK3PXP",
      uri: "otpauth://totp/Test",
    });

    const { result } = renderHook(() => useTOTP(), { wrapper });

    let res: any;
    await act(async () => {
      res = await result.current.enrollTOTP();
    });

    expect(res.ok).toBe(true);
    expect(res.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("usePasskeys calls client.listWebAuthnCredentials and sets credentials state", async () => {
    const { client, wrapper } = createWrapper();
    const mockCredentials = [
      {
        id: "passkey_1",
        name: "Test Passkey",
        credentialId: "cred_1",
        signCount: 0,
        createdAt: "2026-08-01T00:00:00Z",
      },
    ];
    vi.spyOn(client, "listWebAuthnCredentials").mockResolvedValue({
      ok: true,
      credentials: mockCredentials,
    });

    const { result } = renderHook(() => usePasskeys(), { wrapper });

    await act(async () => {
      await result.current.listCredentials();
    });

    expect(result.current.credentials).toEqual(mockCredentials);
    expect(result.current.isLoading).toBe(false);
  });
});
