import { describe, expect, it } from "vitest";
import { AuthnError, AuthnErrorCode } from "../types";

/**
 * The engine sends a stable snake_case `code` on every error body and documents
 * it as the only field clients may branch on. These tests assert against that
 * wire format rather than against the client's own enum names, because a test
 * that mocks `code: "EMAIL_ALREADY_EXISTS"` passes whether or not the
 * translation exists — the engine never sends that string.
 */
describe("AuthnError.fromResponse — engine wire codes", () => {
  it("maps a rejected password to a validation error rather than the unknown catch-all", () => {
    const err = AuthnError.fromResponse(400, {
      error: "password does not meet policy requirements",
      code: "validation_failed",
    });

    expect(err.code).toBe(AuthnErrorCode.VALIDATION_ERROR);
    expect(err.statusCode).toBe(400);
    expect(err.isRetryable).toBe(false);
  });

  it("keeps the criteria a rejected password missed", () => {
    // The engine merges supporting facts into the body alongside `error` and
    // `code`, not under a `details` key.
    const err = AuthnError.fromResponse(400, {
      error: "password does not meet policy requirements",
      code: "validation_failed",
      missing_criteria: ["uppercase", "numeric"],
    });

    expect(err.details?.["missing_criteria"]).toEqual(["uppercase", "numeric"]);
  });

  it("flattens a nested details object alongside top-level facts", () => {
    const err = AuthnError.fromResponse(429, {
      error: "too many attempts",
      code: "rate_limited",
      retry_after: 30,
      details: { limit: 5 },
    });

    expect(err.details).toEqual({ retry_after: 30, limit: 5 });
  });

  it("carries no details when the body is only the two contract fields", () => {
    const err = AuthnError.fromResponse(404, { error: "not found", code: "not_found" });

    expect(err.details).toBeUndefined();
  });

  it("separates a taken email from every other conflict", () => {
    const taken = AuthnError.fromResponse(409, {
      error: "user with this email already exists",
      code: "already_exists",
    });
    const other = AuthnError.fromResponse(409, {
      error: "that slug is in use",
      code: "conflict",
    });

    expect(taken.code).toBe(AuthnErrorCode.EMAIL_ALREADY_EXISTS);
    expect(other.code).toBe(AuthnErrorCode.CONFLICT);
  });

  it("separates a disabled account from an ordinary refusal, since retrying cannot fix it", () => {
    const disabled = AuthnError.fromResponse(403, {
      error: "this account has been suspended",
      code: "account_disabled",
    });
    const forbidden = AuthnError.fromResponse(403, {
      error: "insufficient permissions",
      code: "insufficient_permissions",
    });

    expect(disabled.code).toBe(AuthnErrorCode.ACCOUNT_DISABLED);
    expect(forbidden.code).toBe(AuthnErrorCode.FORBIDDEN);
  });

  it("separates a wrong second factor from an expired challenge", () => {
    const wrongCode = AuthnError.fromResponse(401, {
      error: "invalid code",
      code: "invalid_mfa_code",
    });
    const expired = AuthnError.fromResponse(401, {
      error: "session expired",
      code: "session_expired",
    });

    expect(wrongCode.code).toBe(AuthnErrorCode.INVALID_MFA_CODE);
    expect(expired.code).toBe(AuthnErrorCode.SESSION_EXPIRED);
  });

  it("reads a full test environment as the client's problem, not a retryable fault", () => {
    const err = AuthnError.fromResponse(403, {
      error: "test environment holds its limit of applications",
      code: "test_quota_exceeded",
    });

    expect(err.code).toBe(AuthnErrorCode.TEST_QUOTA_EXCEEDED);
    expect(err.isRetryable).toBe(false);
  });

  it("reads a rejected origin as a misconfigured client rather than a refusal to relay", () => {
    const err = AuthnError.fromResponse(403, {
      error: "origin not allowed",
      code: "origin_not_allowed",
    });

    expect(err.code).toBe(AuthnErrorCode.INVALID_CONFIG);
  });

  it("falls back to the status when nothing between client and engine sent a code", () => {
    // What a proxy or load balancer answers with.
    const gateway = AuthnError.fromResponse(502, { error: "Bad Gateway" });
    const badRequest = AuthnError.fromResponse(400, { error: "Bad Request" });

    expect(gateway.code).toBe(AuthnErrorCode.SERVER_ERROR);
    expect(gateway.isRetryable).toBe(true);
    expect(badRequest.code).toBe(AuthnErrorCode.INVALID_PARAMS);
  });

  it("accepts its own serialized form, for an error relayed back through toJSON", () => {
    const original = AuthnError.fromResponse(403, {
      error: "this account has been suspended",
      code: "account_disabled",
    });
    const relayed = AuthnError.fromResponse(403, original.toJSON());

    expect(relayed.code).toBe(AuthnErrorCode.ACCOUNT_DISABLED);
  });

  it("prefers the code over the status, since one status covers several faults", () => {
    // 400 alone cannot distinguish a malformed body from a policy-rejected
    // password, and only the second is worth pointing a form field at.
    const malformed = AuthnError.fromResponse(400, {
      error: "invalid request body",
      code: "invalid_request_body",
    });
    const rejected = AuthnError.fromResponse(400, {
      error: "password does not meet policy requirements",
      code: "validation_failed",
    });

    expect(malformed.code).toBe(AuthnErrorCode.INVALID_PARAMS);
    expect(rejected.code).toBe(AuthnErrorCode.VALIDATION_ERROR);
  });
});
