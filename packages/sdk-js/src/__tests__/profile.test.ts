import { describe, expect, it, vi } from "vitest";
import { AuthnClient } from "../client";
import { AuthnErrorCode } from "../types";

const PK = "pk_test_demo12345678901234567890123456789012";

function mockJson(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    text: async () => JSON.stringify(body),
  });
}

/** Queue one more JSON response on an existing mock fetch. */
function queue(mockFetch: ReturnType<typeof vi.fn>, body: unknown, status = 200) {
  mockFetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    text: async () => JSON.stringify(body),
  });
}

async function authenticatedClient(mockFetch: ReturnType<typeof vi.fn>) {
  const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });

  queue(mockFetch, {
    user: {
      id: "usr_profile_owner",
      email: "owner@example.com",
      email_verified: true,
      status: "active",
      created_at: "2026-08-01T00:00:00Z",
    },
    access_token: "jwt_access_token",
    expires_at: Math.floor(Date.now() / 1000) + 900,
  });

  await client.login({ email: "owner@example.com", password: "SuperSecret123!" });
  return client;
}

const PROFILE_FIXTURE = {
  id: "usr_profile_owner",
  tenant_id: "tnt_default",
  email: "owner@example.com",
  email_verified: true,
  name: "Ada Lovelace",
  phone_number: "+441234567890",
  phone_verified: false,
  recovery_email: "backup@example.com",
  recovery_email_verified: true,
  avatar_url: "https://cdn.example.com/a.png",
  locale: "en-GB",
  metadata: { plan: "pro" },
  created_at: "2026-08-01T00:00:00Z",
  updated_at: "2026-08-06T12:00:00Z",
};

describe("AuthnClient — getProfile()", () => {
  it("maps the full profile payload into camelCase", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, PROFILE_FIXTURE);

    const result = await client.getProfile();

    expect(result.ok).toBe(true);
    if (result.ok) {
      const p = result.profile;
      expect(p.id).toBe("usr_profile_owner");
      expect(p.tenantId).toBe("tnt_default");
      expect(p.email).toBe("owner@example.com");
      expect(p.emailVerified).toBe(true);
      expect(p.name).toBe("Ada Lovelace");
      expect(p.phoneNumber).toBe("+441234567890");
      expect(p.phoneVerified).toBe(false);
      expect(p.recoveryEmail).toBe("backup@example.com");
      expect(p.recoveryEmailVerified).toBe(true);
      expect(p.avatarUrl).toBe("https://cdn.example.com/a.png");
      expect(p.locale).toBe("en-GB");
      expect(p.metadata).toEqual({ plan: "pro" });
      expect(p.createdAt).toBe("2026-08-01T00:00:00Z");
      expect(p.updatedAt).toBe("2026-08-06T12:00:00Z");
    }

    const [url, init] = mockFetch.mock.calls[1];
    expect(url).toContain("/v1/client/user/profile");
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("include");
  });

  it("coerces omitted optional booleans to false rather than undefined", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, {
      id: "usr_minimal",
      tenant_id: "tnt_default",
      email: "min@example.com",
      email_verified: false,
      created_at: "2026-08-01T00:00:00Z",
      updated_at: "2026-08-01T00:00:00Z",
    });

    const result = await client.getProfile();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.profile.phoneVerified).toBe(false);
      expect(result.profile.recoveryEmailVerified).toBe(false);
      expect(result.profile.name).toBeUndefined();
    }
  });

  it("surfaces a 401 as an auth error", async () => {
    const mockFetch = mockJson({ error: "authentication required" }, 401);
    const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });

    const result = await client.getProfile();

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe(AuthnErrorCode.UNAUTHORIZED);
  });
});

describe("AuthnClient — updateProfile()", () => {
  it("PATCHes only the fields the caller supplied", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { ...PROFILE_FIXTURE, name: "Grace Hopper" });

    const result = await client.updateProfile({ name: "Grace Hopper" });

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.profile.name).toBe("Grace Hopper");

    const [url, init] = mockFetch.mock.calls[1];
    expect(url).toContain("/v1/client/user/profile");
    expect(init.method).toBe("PATCH");
    // locale / avatar_url / metadata must be absent, not null.
    expect(JSON.parse(init.body)).toEqual({ name: "Grace Hopper" });
  });

  it("maps every camelCase field to its snake_case wire name", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, PROFILE_FIXTURE);

    await client.updateProfile({
      name: "Ada",
      avatarUrl: "https://cdn.example.com/new.png",
      locale: "fr-FR",
      metadata: { tier: "gold" },
    });

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({
      name: "Ada",
      avatar_url: "https://cdn.example.com/new.png",
      locale: "fr-FR",
      metadata: { tier: "gold" },
    });
  });

  it("sends an empty body when called with no arguments", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, PROFILE_FIXTURE);

    await client.updateProfile();

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({});
  });

  it("preserves an explicit empty string, which clears a field server-side", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, PROFILE_FIXTURE);

    await client.updateProfile({ avatarUrl: "" });

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({ avatar_url: "" });
  });

  it("surfaces a 400 validation failure from the server", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { error: "locale is not a valid BCP-47 tag" }, 400);

    const result = await client.updateProfile({ locale: "!!!" });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.statusCode).toBe(400);
  });
});

describe("AuthnClient — changePassword()", () => {
  it("posts current_password and new_password", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { message: "password updated successfully" });

    const result = await client.changePassword("OldPassword1!", "NewPassword2!");

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.message).toBe("password updated successfully");

    const [url, init] = mockFetch.mock.calls[1];
    expect(url).toContain("/v1/client/user/password");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({
      current_password: "OldPassword1!",
      new_password: "NewPassword2!",
    });
  });

  it("returns a validation error when the new password is too short", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    const callsBefore = mockFetch.mock.calls.length;

    const result = await client.changePassword("OldPassword1!", "short");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(AuthnErrorCode.INVALID_PARAMS);
      expect(result.error.details).toEqual({ field: "password" });
    }
    expect(mockFetch.mock.calls.length).toBe(callsBefore);
  });

  it("returns a validation error when the current password is empty", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    const result = await client.changePassword("", "NewPassword2!");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.details).toEqual({ field: "currentPassword" });
    }
  });

  it("surfaces a 401 when the current password is wrong", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { error: "incorrect current password" }, 401);
    // The 401 interceptor would try to refresh; deny it so the error surfaces.
    queue(mockFetch, { error: "refresh rejected" }, 401);

    const result = await client.changePassword("WrongPassword1!", "NewPassword2!");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.statusCode).toBe(401);
  });
});

describe("AuthnClient — email change", () => {
  it("posts the new email and does not expose the server's verification_token", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, {
      message: "email verification link sent to new email address",
      verification_token: "tok_leaked_by_backend",
    });

    const result = await client.requestEmailChange("new@example.com");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.message).toBe("email verification link sent to new email address");
      // The token must not be surfaced — relying on it defeats mailbox verification.
      expect(JSON.stringify(result)).not.toContain("tok_leaked_by_backend");
    }

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({
      new_email: "new@example.com",
    });
  });

  it("returns a validation error for a malformed email", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    const callsBefore = mockFetch.mock.calls.length;

    const result = await client.requestEmailChange("not-an-email");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe(AuthnErrorCode.INVALID_PARAMS);
      expect(result.error.details).toEqual({ field: "email" });
    }
    expect(mockFetch.mock.calls.length).toBe(callsBefore);
  });

  it("surfaces a 409 when the address is already in use", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(
      mockFetch,
      { error: "email address is already in use by another account" },
      409,
    );

    const result = await client.requestEmailChange("taken@example.com");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.statusCode).toBe(409);
  });

  it("verifies the change via GET with the token as a query parameter", async () => {
    const mockFetch = mockJson({
      message: "primary email address updated and verified successfully",
    });
    const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });

    const result = await client.verifyEmailChange("tok_from_email");

    expect(result.ok).toBe(true);

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain("/v1/client/user/email/verify");
    expect(url).toContain("token=tok_from_email");
    expect(init.method).toBe("GET");
  });

  it("returns a validation error for an empty verification token", async () => {
    const mockFetch = mockJson({});
    const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });

    const result = await client.verifyEmailChange("");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.details).toEqual({ field: "token" });
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe("AuthnClient — recovery email", () => {
  it("reads the configured recovery email and its verification state", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, {
      recovery_email: "backup@example.com",
      recovery_email_verified: true,
    });

    const result = await client.getRecoveryEmail();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.recoveryEmail).toBe("backup@example.com");
      expect(result.recoveryEmailVerified).toBe(true);
    }
  });

  it("returns an empty string when no recovery email is configured", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { recovery_email_verified: false });

    const result = await client.getRecoveryEmail();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.recoveryEmail).toBe("");
      expect(result.recoveryEmailVerified).toBe(false);
    }
  });

  it("sets a recovery email without exposing the verification token", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, {
      message: "secondary recovery email verification link sent",
      verification_token: "tok_recovery_leaked",
    });

    const result = await client.setRecoveryEmail("backup@example.com");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(JSON.stringify(result)).not.toContain("tok_recovery_leaked");
    }

    expect(JSON.parse(mockFetch.mock.calls[1][1].body)).toEqual({
      recovery_email: "backup@example.com",
    });
  });

  it("returns a validation error for a malformed recovery email", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    const result = await client.setRecoveryEmail("nope");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.details).toEqual({ field: "email" });
  });

  it("verifies the recovery email via GET with a token query parameter", async () => {
    const mockFetch = mockJson({ message: "secondary recovery email verified successfully" });
    const client = new AuthnClient({ publishableKey: PK, fetch: mockFetch as any });

    const result = await client.verifyRecoveryEmail("tok_recovery");

    expect(result.ok).toBe(true);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain("/v1/client/user/recovery-email/verify");
    expect(url).toContain("token=tok_recovery");
    expect(init.method).toBe("GET");
  });

  it("deletes the recovery email with a DELETE request", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { message: "secondary recovery email removed successfully" });

    const result = await client.deleteRecoveryEmail();

    expect(result.ok).toBe(true);
    const [url, init] = mockFetch.mock.calls[1];
    expect(url).toContain("/v1/client/user/recovery-email");
    expect(init.method).toBe("DELETE");
  });
});

describe("AuthnClient — social accounts", () => {
  it("maps the linked account list into camelCase", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, {
      social_accounts: [
        {
          provider: "google",
          provider_user_id: "google_1234",
          email: "owner@gmail.com",
          connected_at: "2026-07-01T08:00:00Z",
        },
        {
          provider: "github",
          provider_user_id: "gh_9876",
          connected_at: "2026-07-15T09:30:00Z",
        },
      ],
    });

    const result = await client.listSocialAccounts();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.accounts).toHaveLength(2);
      expect(result.accounts[0].provider).toBe("google");
      expect(result.accounts[0].providerUserId).toBe("google_1234");
      expect(result.accounts[0].email).toBe("owner@gmail.com");
      expect(result.accounts[0].connectedAt).toBe("2026-07-01T08:00:00Z");
      // `email` is omitempty server-side.
      expect(result.accounts[1].email).toBeUndefined();
    }
  });

  it("returns an empty array when the server omits the key", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, {});

    const result = await client.listSocialAccounts();

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.accounts).toEqual([]);
  });

  it("unlinks a provider via DELETE on a path-encoded provider segment", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { provider: "google", message: "social account unlinked successfully" });

    const result = await client.unlinkSocialAccount("google");

    expect(result.ok).toBe(true);
    const [url, init] = mockFetch.mock.calls[1];
    expect(url).toContain("/v1/client/user/social-accounts/google");
    expect(init.method).toBe("DELETE");
  });

  it("surfaces a 403 when unlinking the last remaining login method", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(
      mockFetch,
      {
        error:
          "cannot unlink social account: user has no password set and this is the only login method",
      },
      403,
    );

    const result = await client.unlinkSocialAccount("google");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe(AuthnErrorCode.FORBIDDEN);
  });

  it("surfaces a 404 when the provider is not connected", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    queue(mockFetch, { error: "social provider is not connected to this account" }, 404);

    const result = await client.unlinkSocialAccount("gitlab");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe(AuthnErrorCode.NOT_FOUND);
  });

  it("returns a validation error for an empty provider", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    const callsBefore = mockFetch.mock.calls.length;

    const result = await client.unlinkSocialAccount("");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.details).toEqual({ field: "provider" });
    expect(mockFetch.mock.calls.length).toBe(callsBefore);
  });
});

describe("AuthnClient — deleteAccount()", () => {
  it("sends the password in the DELETE body and clears the local session", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    expect(client.isAuthenticated()).toBe(true);

    queue(mockFetch, { message: "user account deleted permanently" });

    const result = await client.deleteAccount("SuperSecret123!");

    expect(result.ok).toBe(true);
    const [url, init] = mockFetch.mock.calls[1];
    expect(url).toContain("/v1/client/user/account");
    expect(init.method).toBe("DELETE");
    expect(JSON.parse(init.body)).toEqual({ password: "SuperSecret123!" });

    expect(client.isAuthenticated()).toBe(false);
    expect(client.getSession()).toBeNull();
    expect(client.getUser()).toBeNull();
  });

  it("notifies auth state listeners with null", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    const listener = vi.fn();
    client.onAuthStateChanged(listener);
    listener.mockClear();

    queue(mockFetch, { message: "user account deleted permanently" });
    await client.deleteAccount("SuperSecret123!");

    expect(listener).toHaveBeenCalledWith(null, null);
  });

  it("keeps the session when the password is rejected", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);

    queue(mockFetch, { error: "incorrect current password" }, 403);

    const result = await client.deleteAccount("WrongPassword!");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.statusCode).toBe(403);
    expect(client.isAuthenticated()).toBe(true);
  });

  it("returns a validation error when no password is supplied", async () => {
    const mockFetch = mockJson({});
    const client = await authenticatedClient(mockFetch);
    const callsBefore = mockFetch.mock.calls.length;

    const result = await client.deleteAccount("");

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.details).toEqual({ field: "password" });
    expect(mockFetch.mock.calls.length).toBe(callsBefore);
    expect(client.isAuthenticated()).toBe(true);
  });
});
