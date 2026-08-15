import { describe, expect, it, vi } from "vitest";
import { AuthnClient } from "../client";
import { AuthnErrorCode } from "../types";
import {
  base64UrlToBuffer,
  bufferToBase64Url,
  formatCreationCredential,
  formatRequestCredential,
  prepareCreationOptions,
  prepareRequestOptions,
} from "../webauthn";

describe("WebAuthn Base64URL Helpers", () => {
  it("should convert ArrayBuffer to base64url and back", () => {
    const original = new Uint8Array([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]); // "Hello World"
    const encoded = bufferToBase64Url(original.buffer);
    expect(encoded).toBe("SGVsbG8gV29ybGQ");

    const decodedBuffer = base64UrlToBuffer(encoded);
    const decodedBytes = new Uint8Array(decodedBuffer);
    expect(Array.from(decodedBytes)).toEqual(Array.from(original));
  });

  it("should prepare creation options converting challenge and user.id to ArrayBuffer", () => {
    const rawOptions = {
      publicKey: {
        challenge: "dGVzdF9jaGFsbGVuZ2U",
        rp: { name: "Authn Test", id: "localhost" },
        user: { id: "dXNyXzEyMw", name: "user@example.com", displayName: "User Example" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [{ type: "public-key", id: "Y3JlZF8xMjM" }],
      },
    };

    const prepared = prepareCreationOptions(rawOptions);
    expect(prepared.challenge).toBeInstanceOf(ArrayBuffer);
    expect(prepared.user.id).toBeInstanceOf(ArrayBuffer);
    expect(prepared.excludeCredentials![0].id).toBeInstanceOf(ArrayBuffer);
  });

  it("should prepare request options converting challenge and allowCredentials to ArrayBuffer", () => {
    const rawOptions = {
      publicKey: {
        challenge: "dGVzdF9jaGFsbGVuZ2U",
        allowCredentials: [{ type: "public-key", id: "Y3JlZF8xMjM" }],
      },
    };

    const prepared = prepareRequestOptions(rawOptions);
    expect(prepared.challenge).toBeInstanceOf(ArrayBuffer);
    expect(prepared.allowCredentials![0].id).toBeInstanceOf(ArrayBuffer);
  });
});

describe("2FA, TOTP & WebAuthn SDK Methods", () => {
  const validPk = "pk_test_demo12345678901234567890123456789012";

  const createClientWithMock = (mockResponse: any, status = 200) => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      headers: new Headers(),
      text: async () => JSON.stringify(mockResponse),
    });

    const client = new AuthnClient({
      publishableKey: validPk,
      fetch: mockFetch as any,
    });

    return { client, mockFetch };
  };

  it("1. enrollTOTP — POST /v1/client/auth/2fa/totp/enroll", async () => {
    const { client, mockFetch } = createClientWithMock({
      secret: "JBSWY3DPEHPK3PXP",
      uri: "otpauth://totp/Authn:user@example.com?secret=JBSWY3DPEHPK3PXP",
    });

    const result = await client.enrollTOTP();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.secret).toBe("JBSWY3DPEHPK3PXP");
      expect(result.uri).toContain("otpauth://");
    }

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/client/auth/2fa/totp/enroll"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("2. confirmTOTP — POST /v1/client/auth/2fa/totp/confirm", async () => {
    const { client, mockFetch } = createClientWithMock({
      message: "TOTP 2FA enabled",
      recovery_codes: ["code1", "code2"],
      recovery_codes_created: true,
    });

    const result = await client.confirmTOTP({ code: "123456" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.message).toBe("TOTP 2FA enabled");
      expect(result.recoveryCodes).toEqual(["code1", "code2"]);
      expect(result.recoveryCodesCreated).toBe(true);
    }
  });

  it("3. disableTOTP — POST /v1/client/auth/2fa/totp/disable", async () => {
    const { client, mockFetch } = createClientWithMock({
      message: "2FA TOTP disabled",
    });

    const result = await client.disableTOTP({ password: "SecretPassword123!" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.message).toBe("2FA TOTP disabled");
    }
  });

  it("4. verifyTOTP — POST /v1/client/auth/2fa/totp/verify", async () => {
    // Session login challenge path
    const { client: client1 } = createClientWithMock({
      user: { id: "usr_123", email: "totp@example.com", email_verified: true, status: "active", created_at: "2026-08-01T00:00:00Z" },
      access_token: "jwt_mfa_verified",
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    });

    const res1 = await client1.verifyTOTP({ code: "123456", mfaToken: "mfa_token_xyz" });
    expect(res1.ok).toBe(true);
    if (res1.ok) {
      expect(res1.session).toBeDefined();
      expect(res1.session?.accessToken).toBe("jwt_mfa_verified");
    }

    // In-session verification path
    const { client: client2 } = createClientWithMock({ valid: true });
    const res2 = await client2.verifyTOTP({ code: "123456" });
    expect(res2.ok).toBe(true);
    if (res2.ok) {
      expect(res2.valid).toBe(true);
    }
  });

  it("5. enrollSMS — POST /v1/client/auth/2fa/sms/enroll", async () => {
    const { client } = createClientWithMock({
      message: "OTP sent via SMS",
      expires_in_seconds: 300,
    });

    const result = await client.enrollSMS({ phoneNumber: "+12025550199" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.expiresInSeconds).toBe(300);
    }
  });

  it("6. confirmSMS — POST /v1/client/auth/2fa/sms/confirm", async () => {
    const { client } = createClientWithMock({
      message: "SMS 2FA confirmed",
      recovery_codes_created: false,
    });

    const result = await client.confirmSMS({ code: "654321" });
    expect(result.ok).toBe(true);
  });

  it("7. disableSMS — DELETE /v1/client/auth/2fa/sms/disable", async () => {
    const { client, mockFetch } = createClientWithMock({
      message: "SMS 2FA disabled",
    });

    const result = await client.disableSMS({ password: "SecretPassword123!" });
    expect(result.ok).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/client/auth/2fa/sms/disable"),
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("8. regenerateRecoveryCodes — POST /v1/client/auth/2fa/recovery-codes/regenerate", async () => {
    const { client } = createClientWithMock({
      message: "recovery codes regenerated",
      recovery_codes: ["rc1", "rc2", "rc3"],
    });

    const result = await client.regenerateRecoveryCodes({ password: "SecretPassword123!" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.recoveryCodes).toHaveLength(3);
    }
  });

  it("9. getRecoveryCodesStatus — GET /v1/client/auth/2fa/recovery-codes/status", async () => {
    const { client, mockFetch } = createClientWithMock({
      remaining_count: 14,
      total_count: 16,
      has_recovery_codes: true,
    });

    const result = await client.getRecoveryCodesStatus();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.status.remainingCount).toBe(14);
      expect(result.status.totalCount).toBe(16);
      expect(result.status.hasRecoveryCodes).toBe(true);
    }
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/client/auth/2fa/recovery-codes/status"),
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("10. beginPasskeyRegistration — POST /v1/client/auth/2fa/webauthn/register/begin", async () => {
    const { client } = createClientWithMock({
      options: { challenge: "abc" },
      session_id: "wasess_123",
    });

    const result = await client.beginPasskeyRegistration();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.sessionId).toBe("wasess_123");
    }
  });

  it("11. finishPasskeyRegistration — POST /v1/client/auth/2fa/webauthn/register/finish", async () => {
    const { client, mockFetch } = createClientWithMock({
      message: "Passkey registered",
      recovery_codes_created: false,
    });

    const result = await client.finishPasskeyRegistration({
      sessionId: "wasess_123",
      name: "My YubiKey",
      credential: { id: "cred_123", rawId: "cred_123" },
    });
    expect(result.ok).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/client/auth/2fa/webauthn/register/finish?session_id=wasess_123&name=My+YubiKey"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("12. beginPasskeyLogin — POST /v1/client/auth/2fa/webauthn/login/begin", async () => {
    const { client } = createClientWithMock({
      options: { challenge: "xyz" },
      session_id: "wasess_login_456",
      user_id: "usr_456",
    });

    const result = await client.beginPasskeyLogin({ mfaToken: "mfa_tok_login" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.sessionId).toBe("wasess_login_456");
      expect(result.userId).toBe("usr_456");
    }
  });

  it("13. finishPasskeyLogin — POST /v1/client/auth/2fa/webauthn/login/finish", async () => {
    const { client, mockFetch } = createClientWithMock({
      user: { id: "usr_passkey", email: "passkey@example.com", email_verified: true, status: "active", created_at: "2026-08-01T00:00:00Z" },
      access_token: "jwt_passkey_login",
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    });

    const result = await client.finishPasskeyLogin({
      mfaToken: "mfa_tok_login",
      sessionId: "wasess_login_456",
      credential: { id: "assertion_123" },
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.accessToken).toBe("jwt_passkey_login");
    }
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/client/auth/2fa/webauthn/login/finish?mfa_token=mfa_tok_login&session_id=wasess_login_456"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("14. listWebAuthnCredentials — GET /v1/client/auth/2fa/webauthn/credentials", async () => {
    const { client, mockFetch } = createClientWithMock({
      credentials: [
        {
          id: "2fa_row_1",
          name: "Work MacBook TouchID",
          credential_id: "cred_handle_1",
          sign_count: 5,
          created_at: "2026-08-05T10:00:00Z",
        },
      ],
    });

    const result = await client.listWebAuthnCredentials();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.credentials).toHaveLength(1);
      expect(result.credentials[0].name).toBe("Work MacBook TouchID");
    }
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/client/auth/2fa/webauthn/credentials"),
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("15. revokeWebAuthnCredential — DELETE /v1/client/auth/2fa/webauthn/credentials/:id", async () => {
    const { client, mockFetch } = createClientWithMock({
      message: "passkey deleted",
    });

    const result = await client.revokeWebAuthnCredential({
      id: "2fa_row_1",
      password: "StepUpPassword123!",
    });
    expect(result.ok).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/client/auth/2fa/webauthn/credentials/2fa_row_1"),
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});
