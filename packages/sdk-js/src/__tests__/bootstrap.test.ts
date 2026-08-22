/**
 * @authn/js — Bootstrap document and the 2FA challenge
 *
 * A password can be correct without signing anyone in. The engine answers that
 * case with 200 and an mfa_token in place of an access_token, so a client that
 * reads every 200 as a session builds one holding no credential — and then
 * reports an authenticated user who cannot make a single authenticated request.
 * These tests hold the client to telling the two apart.
 */

import { describe, expect, it, vi } from "vitest";
import { AuthnClient } from "../client";

const publishableKey = "pk_test_demo12345678901234567890123456789012";

/** jsonFetch answers every call with status and body. */
function jsonFetch(status: number, body: unknown): ReturnType<typeof vi.fn> {
  return vi.fn().mockResolvedValue({
    ok: status < 400,
    status,
    headers: new Headers(),
    text: async () => JSON.stringify(body),
  });
}

const challengeBody = {
  user: {
    id: "usr_2fa_123",
    email: "gated@example.com",
    email_verified: true,
    name: "Gated User",
    status: "active",
    created_at: "2026-08-01T00:00:00Z",
  },
  mfa_required: true,
  mfa_token: "mfa_challenge_token",
  methods: ["passkey", "totp", "backup_code"],
};

describe("AuthnClient 2FA challenge on login", () => {
  it("reports the challenge instead of a session", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, challengeBody) as never,
    });

    const result = await client.login({
      email: "gated@example.com",
      password: "SuperSecret123!",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.mfaRequired).toBe(true);
    expect(result.mfaToken).toBe("mfa_challenge_token");
    expect(result.session).toBeUndefined();
    expect(result.user?.email).toBe("gated@example.com");
  });

  it("stores no session, so nothing reports the user as signed in", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, challengeBody) as never,
    });

    await client.login({
      email: "gated@example.com",
      password: "SuperSecret123!",
    });

    // The whole hazard in one assertion: a stored session here would let a
    // route guard admit someone who has cleared only the first factor.
    expect(client.isAuthenticated()).toBe(false);
    expect(client.getSession()).toBeNull();
    expect(client.getToken()).toBeNull();
    expect(client.getUser()).toBeNull();
  });

  it("preserves the engine's method order", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, challengeBody) as never,
    });

    const result = await client.login({
      email: "gated@example.com",
      password: "SuperSecret123!",
    });

    // The engine sorts by last use so a challenge opens on the factor its owner
    // reached for last time. Normalising through a Set would lose that.
    expect(result.ok && result.methods).toEqual([
      "passkey",
      "totp",
      "backup_code",
    ]);
  });

  it("drops a method it has no screen for", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, {
        ...challengeBody,
        methods: ["totp", "carrier_pigeon"],
      }) as never,
    });

    const result = await client.login({
      email: "gated@example.com",
      password: "SuperSecret123!",
    });

    expect(result.ok && result.methods).toEqual(["totp"]);
  });

  it("falls back to TOTP rather than offering nothing", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, { ...challengeBody, methods: [] }) as never,
    });

    const result = await client.login({
      email: "gated@example.com",
      password: "SuperSecret123!",
    });

    // Reaching here means the names drifted. Offering the one factor every
    // tenant has is recoverable; offering an empty list is a dead end.
    expect(result.ok && result.methods).toEqual(["totp"]);
  });

  it("still establishes a session when no factor is outstanding", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, {
        user: challengeBody.user,
        access_token: "jwt_access_token",
        refresh_token: "refresh_token_value",
        expires_at: Math.floor(Date.now() / 1000) + 900,
      }) as never,
    });

    const result = await client.login({
      email: "gated@example.com",
      password: "SuperSecret123!",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.mfaRequired).toBeUndefined();
    expect(result.session?.accessToken).toBe("jwt_access_token");
    expect(client.isAuthenticated()).toBe(true);
  });
});

const appConfigBody = {
  application: { id: "app_123", name: "Acme", environment: "test" },
  tenant: { name: "Acme Inc", slug: "acme" },
  branding: {
    app_name: "Acme Auth",
    logo_url: "https://cdn.example.com/logo.svg",
    logo_dark_url: "",
    favicon_url: "",
    primary_color: "#ffffff",
    background_color: "#000000",
    text_color: "",
    button_text_color: "",
    font_family: "",
    support_url: "https://acme.example.com/help",
    terms_url: "",
    privacy_url: "",
    custom_css: "",
  },
  sign_in_methods: {
    password: true,
    magic_link: false,
    passkey: true,
    enterprise_sso: false,
    social_providers: ["github", "google"],
  },
  second_factors: {
    totp: true,
    sms: false,
    passkey: true,
    recovery_codes: true,
    push: false,
  },
  password_rules: {
    min_length: 12,
    max_length: 128,
    require_uppercase: true,
    require_lowercase: true,
    require_numeric: true,
    require_special: false,
    enforced: true,
  },
  email_verification: { required: true, mode: "soft" },
  account_recovery: {
    guardians: true,
    phone_otp: false,
    email_otp: true,
    old_password: true,
    security_questions: false,
    min_guardians: 2,
    max_guardians: 5,
  },
};

describe("AuthnClient getAppConfig", () => {
  it("fetches the bootstrap document and camelCases it", async () => {
    const mockFetch = jsonFetch(200, appConfigBody);
    const client = new AuthnClient({
      publishableKey,
      endpoint: "http://localhost:8080",
      fetch: mockFetch as never,
    });

    const result = await client.getAppConfig();

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(mockFetch.mock.calls[0][0]).toBe(
      "http://localhost:8080/v1/client/app-config",
    );
    expect(result.config.application.environment).toBe("test");
    expect(result.config.signInMethods.magicLink).toBe(false);
    expect(result.config.signInMethods.socialProviders).toEqual([
      "github",
      "google",
    ]);
    expect(result.config.passwordRules.minLength).toBe(12);
    expect(result.config.passwordRules.requireSpecial).toBe(false);
    expect(result.config.emailVerification.mode).toBe("soft");
    expect(result.config.accountRecovery.maxGuardians).toBe(5);
    expect(result.config.branding.supportUrl).toBe(
      "https://acme.example.com/help",
    );
  });

  it("reads an unrecognised verification mode as the stricter one", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, {
        ...appConfigBody,
        email_verification: { required: true, mode: "lenient" },
      }) as never,
    });

    const result = await client.getAppConfig();

    // Defaulting to "soft" would admit an unverified user the tenant may have
    // meant to block.
    expect(result.ok && result.config.emailVerification.mode).toBe("hard");
  });

  it("reads an unrecognised environment as test", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(200, {
        ...appConfigBody,
        application: { id: "app_123", name: "Acme", environment: "staging" },
      }) as never,
    });

    const result = await client.getAppConfig();

    // A test-mode banner shown in error is a cosmetic mistake; one withheld in
    // error lets someone believe test data is live.
    expect(result.ok && result.config.application.environment).toBe("test");
  });

  it("surfaces a refused key as an error rather than throwing", async () => {
    const client = new AuthnClient({
      publishableKey,
      fetch: jsonFetch(401, {
        error: { code: "unauthorized", message: "invalid publishable key" },
      }) as never,
    });

    const result = await client.getAppConfig();

    expect(result.ok).toBe(false);
  });
});
