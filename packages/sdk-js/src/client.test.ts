import { describe, expect, it, vi } from "vitest";
import { AuthnClient } from "./client";
import { generateCodeChallenge, generateCodeVerifier, generatePKCEPair } from "./pkce";
import { AuthnError, AuthnErrorCode } from "./types";

describe("AuthnClient Initialization & Validation", () => {
  it("should throw an error when initialized with an invalid publishable key format", () => {
    expect(() => {
      new AuthnClient({ publishableKey: "invalid_key" });
    }).toThrow(AuthnError);
  });

  it("should throw an error when initialized with a secret key", () => {
    expect(() => {
      new AuthnClient({ publishableKey: "sk_test_12345678901234567890123456789012" });
    }).toThrow("Secret keys must never be used in client-side code");
  });

  it("should initialize successfully with a valid publishable key", () => {
    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      endpoint: "http://localhost:8080",
    });
    expect(client).toBeDefined();
    expect(client.isAuthenticated()).toBe(false);
    expect(client.getUser()).toBeNull();
    expect(client.getToken()).toBeNull();
    expect(client.getSession()).toBeNull();
  });
});

describe("AuthnClient Sign Up Flow", () => {
  it("should return a session on successful signup", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          user: {
            id: "usr_signup_123",
            email: "signup@example.com",
            email_verified: false,
            status: "active",
            created_at: "2026-08-01T00:00:00Z",
          },
          access_token: "jwt_signup_access_token",
          expires_at: Math.floor(Date.now() / 1000) + 900,
        }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.signUp({
      email: "signup@example.com",
      password: "SuperSecret123!",
      name: "Signup User",
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.user.id).toBe("usr_signup_123");
      expect(result.session.accessToken).toBe("jwt_signup_access_token");
      expect(client.isAuthenticated()).toBe(true);
      expect(client.getUser()?.email).toBe("signup@example.com");
      expect(client.getToken()).toBe("jwt_signup_access_token");
    }
  });

  it("should handle signup email already exists error", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 409,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          code: "EMAIL_ALREADY_EXISTS",
          message: "An account with this email already exists",
        }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.signUp({
      email: "existing@example.com",
      password: "SuperSecret123!",
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(AuthnErrorCode.EMAIL_ALREADY_EXISTS);
    }
  });
});

describe("AuthnClient Login Flow", () => {
  it("should return a session on successful login", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          user: {
            id: "usr_123",
            email: "test@example.com",
            email_verified: true,
            status: "active",
            created_at: "2026-08-01T00:00:00Z",
          },
          access_token: "jwt_token_abc",
          expires_at: Math.floor(Date.now() / 1000) + 900,
        }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.login({
      email: "test@example.com",
      password: "SuperSecret123!",
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.user.email).toBe("test@example.com");
      expect(result.session.accessToken).toBe("jwt_token_abc");
      expect(client.isAuthenticated()).toBe(true);
      expect(client.getSession()?.accessToken).toBe("jwt_token_abc");
    }
  });

  it("should handle login credentials error", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password",
        }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.login({
      email: "test@example.com",
      password: "WrongPassword123!",
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(AuthnErrorCode.INVALID_CREDENTIALS);
    }
  });
});

describe("AuthnClient Magic Link & Email Verification Flows", () => {
  it("should send magic link successfully", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ message: "Magic link sent to email" }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.sendMagicLink({ email: "magic@example.com" });
    expect(result.ok).toBe(true);
  });

  it("should verify magic link and establish session", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          user: {
            id: "usr_magic_123",
            email: "magic@example.com",
            email_verified: true,
            status: "active",
            created_at: "2026-08-01T00:00:00Z",
          },
          access_token: "jwt_magic_access_token",
          expires_at: Math.floor(Date.now() / 1000) + 900,
        }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.verifyMagicLink({ token: "magic_token_xyz" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.user.id).toBe("usr_magic_123");
      expect(client.isAuthenticated()).toBe(true);
    }
  });

  it("should verify email and update active session", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ message: "Email verified successfully" }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.verifyEmail({ token: "verify_token_123" });
    expect(result.ok).toBe(true);
  });

  it("should resend email verification successfully", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ message: "Verification email resent" }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.resendVerification({ email: "unverified@example.com" });
    expect(result.ok).toBe(true);
  });
});

describe("AuthnClient Silent Refresh & Session Lifecycle", () => {
  it("should refresh session and return updated tokens", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          user: {
            id: "usr_123",
            email: "test@example.com",
            email_verified: true,
            status: "active",
            created_at: "2026-08-01T00:00:00Z",
          },
          access_token: "jwt_refreshed_access_token",
          expires_at: Math.floor(Date.now() / 1000) + 900,
        }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.refreshSession();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.accessToken).toBe("jwt_refreshed_access_token");
      expect(client.getToken()).toBe("jwt_refreshed_access_token");
    }
  });

  it("should notify onAuthStateChanged listeners on state transition", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          user: {
            id: "usr_123",
            email: "test@example.com",
            email_verified: true,
            status: "active",
            created_at: "2026-08-01T00:00:00Z",
          },
          access_token: "jwt_token_abc",
          expires_at: Math.floor(Date.now() / 1000) + 900,
        }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const listener = vi.fn();
    const unsubscribe = client.onAuthStateChanged(listener);

    // Immediate initial call
    expect(listener).toHaveBeenLastCalledWith(null, null);

    // Trigger login
    await client.login({ email: "test@example.com", password: "Password123!" });
    expect(listener).toHaveBeenCalledTimes(2);
    expect(client.getUser()?.email).toBe("test@example.com");

    unsubscribe();
  });

  it("should sign out and clear session state", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify({ message: "Logged out" }),
    });

    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
      fetch: mockFetch as any,
    });

    const result = await client.signOut();
    expect(result.ok).toBe(true);
    expect(client.isAuthenticated()).toBe(false);
    expect(client.getUser()).toBeNull();
  });

  it("should prevent further calls after destroy()", async () => {
    const client = new AuthnClient({
      publishableKey: "pk_test_demo12345678901234567890123456789012",
    });

    client.destroy();
    await expect(client.login({ email: "test@example.com", password: "123" })).rejects.toThrow(
      "AuthnClient instance has been destroyed",
    );
  });
});

describe("PKCE Utility Functions", () => {
  it("should generate a 43+ character high-entropy code verifier", () => {
    const verifier = generateCodeVerifier();
    expect(typeof verifier).toBe("string");
    expect(verifier.length).toBeGreaterThanOrEqual(43);
  });

  it("should derive a valid base64url SHA-256 code challenge from a verifier", async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    expect(typeof challenge).toBe("string");
    expect(challenge.length).toBeGreaterThan(20);
  });

  it("should generate a complete PKCE pair", async () => {
    const pair = await generatePKCEPair();
    expect(pair.codeVerifier).toBeDefined();
    expect(pair.codeChallenge).toBeDefined();
    expect(pair.codeChallengeMethod).toBe("S256");
  });
});
