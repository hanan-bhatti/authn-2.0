import React from "react";
import { describe, expect, it, vi } from "vitest";
import { act, render, renderHook } from "@testing-library/react";
import { AuthnClient, AuthnError, AuthnErrorCode } from "@authn/js";
import {
  AuthnProvider,
  useAuth,
  useMagicLink,
  useSignIn,
  useSignOut,
  useSignUp,
  useUser,
} from "./index";

describe("<AuthnProvider> Lifecycle & Context", () => {
  it("should throw an error when hooks are used outside of <AuthnProvider>", () => {
    expect(() => renderHook(() => useAuth())).toThrow("must be used within an <AuthnProvider>");
    expect(() => renderHook(() => useUser())).toThrow("must be used within an <AuthnProvider>");
    expect(() => renderHook(() => useSignIn())).toThrow("must be used within an <AuthnProvider>");
    expect(() => renderHook(() => useSignUp())).toThrow("must be used within an <AuthnProvider>");
    expect(() => renderHook(() => useSignOut())).toThrow("must be used within an <AuthnProvider>");
    expect(() => renderHook(() => useMagicLink())).toThrow("must be used within an <AuthnProvider>");
  });

  it("should throw a runtime error if neither publishableKey nor client is provided", () => {
    expect(() =>
      render(
        <AuthnProvider {...({} as any)}>
          <div>Child</div>
        </AuthnProvider>,
      ),
    ).toThrow("<AuthnProvider> requires either a `publishableKey` string or a pre-constructed `client` instance.");
  });

  it("should mount cleanly with a publishableKey and destroy client on unmount", () => {
    const { unmount } = render(
      <AuthnProvider publishableKey="pk_test_demo12345678901234567890123456789012">
        <div>Child</div>
      </AuthnProvider>,
    );
    expect(() => unmount()).not.toThrow();
  });

  it("should accept a pre-constructed client instance and not destroy external client on unmount", () => {
    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
    });
    const destroySpy = vi.spyOn(client, "destroy");

    const { unmount } = render(
      <AuthnProvider client={client}>
        <div>Child</div>
      </AuthnProvider>,
    );

    unmount();
    expect(destroySpy).not.toHaveBeenCalled();
  });
});

describe("React Auth Hooks Behavior", () => {
  const publishableKey = "pk_test_demo12345678901234567890123456789012";

  const wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <AuthnProvider publishableKey={publishableKey}>
      {children}
    </AuthnProvider>
  );

  it("useAuth() and useUser() should return state and subscriber updates", async () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    const { result: userResult } = renderHook(() => useUser(), { wrapper });

    expect(result.current.isLoading).toBe(false);
    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.user).toBeNull();
    expect(userResult.current).toBeNull();
  });

  it("useSignIn() should handle login success, loading, error, and reset()", async () => {
    const client = new AuthnClient({ publishableKey });
    vi.spyOn(client, "login").mockResolvedValue({
      ok: true,
      session: {
        accessToken: "jwt_token_abc",
        expiresAt: 9999999999,
        user: {
          id: "usr_123",
          email: "test@example.com",
          emailVerified: true,
          status: "active",
          createdAt: "2026-08-01T00:00:00Z",
        },
      },
    });

    const customWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
      <AuthnProvider client={client}>{children}</AuthnProvider>
    );

    const { result } = renderHook(() => useSignIn(), { wrapper: customWrapper });

    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();

    let loginRes: any;
    await act(async () => {
      loginRes = await result.current.signIn({ email: "test@example.com", password: "Password123!" });
    });

    expect(loginRes.ok).toBe(true);
    expect(result.current.isLoading).toBe(false);

    // Mock error response
    vi.spyOn(client, "login").mockResolvedValue({
      ok: false,
      error: new AuthnError({
        message: "Invalid email or password",
        code: AuthnErrorCode.INVALID_CREDENTIALS,
      }),
    });

    await act(async () => {
      await result.current.signIn({ email: "test@example.com", password: "Wrong" });
    });

    expect(result.current.error?.code).toBe(AuthnErrorCode.INVALID_CREDENTIALS);

    act(() => {
      result.current.reset();
    });

    expect(result.current.error).toBeNull();
  });

  it("useSignUp() should handle sign-up success, error, and reset()", async () => {
    const client = new AuthnClient({ publishableKey });
    vi.spyOn(client, "signUp").mockResolvedValue({
      ok: true,
      session: {
        accessToken: "jwt_token_signup",
        expiresAt: 9999999999,
        user: {
          id: "usr_signup_123",
          email: "signup@example.com",
          emailVerified: false,
          status: "active",
          createdAt: "2026-08-01T00:00:00Z",
        },
      },
    });

    const customWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
      <AuthnProvider client={client}>{children}</AuthnProvider>
    );

    const { result } = renderHook(() => useSignUp(), { wrapper: customWrapper });

    let signUpRes: any;
    await act(async () => {
      signUpRes = await result.current.signUp({ email: "signup@example.com", password: "Password123!" });
    });

    expect(signUpRes.ok).toBe(true);
    expect(result.current.error).toBeNull();
  });

  it("useSignOut() should handle sign-out success and reset()", async () => {
    const client = new AuthnClient({ publishableKey });
    vi.spyOn(client, "signOut").mockResolvedValue({ ok: true });

    const customWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
      <AuthnProvider client={client}>{children}</AuthnProvider>
    );

    const { result } = renderHook(() => useSignOut(), { wrapper: customWrapper });

    let signOutRes: any;
    await act(async () => {
      signOutRes = await result.current.signOut();
    });

    expect(signOutRes.ok).toBe(true);
    expect(result.current.error).toBeNull();
  });

  it("useMagicLink() should handle sendMagicLink, verifyMagicLink, and error states", async () => {
    const client = new AuthnClient({ publishableKey });
    vi.spyOn(client, "sendMagicLink").mockResolvedValue({ ok: true });
    vi.spyOn(client, "verifyMagicLink").mockResolvedValue({
      ok: true,
      session: {
        accessToken: "jwt_magic",
        expiresAt: 9999999999,
        user: {
          id: "usr_magic",
          email: "magic@example.com",
          emailVerified: true,
          status: "active",
          createdAt: "2026-08-01T00:00:00Z",
        },
      },
    });

    const customWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
      <AuthnProvider client={client}>{children}</AuthnProvider>
    );

    const { result } = renderHook(() => useMagicLink(), { wrapper: customWrapper });

    let sendRes: any;
    await act(async () => {
      sendRes = await result.current.sendMagicLink({ email: "magic@example.com" });
    });
    expect(sendRes.ok).toBe(true);

    let verifyRes: any;
    await act(async () => {
      verifyRes = await result.current.verifyMagicLink({ token: "magic_token_123" });
    });
    expect(verifyRes.ok).toBe(true);
  });
});
