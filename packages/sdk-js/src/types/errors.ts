/**
 * @authn/js — Error Types & AuthnError Class
 *
 * @packageDocumentation
 */

export enum AuthnErrorCode {
  NETWORK_ERROR = "NETWORK_ERROR",
  TIMEOUT = "TIMEOUT",
  /**
   * The request was abandoned because the client was destroyed — a component
   * unmounted, a route changed. Distinct from TIMEOUT: the server was never
   * given the chance to answer, so nothing is known about its state, and
   * retrying is pointless because the caller no longer exists.
   */
  CANCELLED = "CANCELLED",
  INVALID_CONFIG = "INVALID_CONFIG",
  INVALID_PARAMS = "INVALID_PARAMS",
  INVALID_PUBLISHABLE_KEY = "INVALID_PUBLISHABLE_KEY",
  UNAUTHORIZED = "UNAUTHORIZED",
  FORBIDDEN = "FORBIDDEN",
  NOT_FOUND = "NOT_FOUND",
  RATE_LIMITED = "RATE_LIMITED",
  VALIDATION_ERROR = "VALIDATION_ERROR",
  EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS",
  /**
   * Something else already holds the value being claimed — an organization slug,
   * a second factor of a kind already enrolled. Distinct from
   * EMAIL_ALREADY_EXISTS because that one has a sign-in link as its remedy and
   * this one does not.
   */
  CONFLICT = "CONFLICT",
  INVALID_CREDENTIALS = "INVALID_CREDENTIALS",
  /**
   * The credential was right but the account may not sign in: banned, suspended,
   * or held after a recovery. Separate from FORBIDDEN because retrying is
   * pointless — the way out is contacting support, not entering a better
   * password.
   */
  ACCOUNT_DISABLED = "ACCOUNT_DISABLED",
  /**
   * The second factor was wrong. A challenge screen keeps the user on the same
   * step for this, where an expired challenge sends them back to the start.
   */
  INVALID_MFA_CODE = "INVALID_MFA_CODE",
  EMAIL_VERIFICATION_REQUIRED = "EMAIL_VERIFICATION_REQUIRED",
  /**
   * The session is valid but this change needs the credential re-entered. Which
   * credential is not the caller's choice: an account holding a password is checked
   * on it, and only one without falls through to an authenticator code.
   *
   * Distinct from UNAUTHORIZED, which both of these arrive as over the wire, because
   * the remedy is the opposite one. UNAUTHORIZED means sign in again; this means the
   * sign-in is fine and the dialog needs a field. A page that conflates them tells
   * someone whose session is working perfectly to start over.
   */
  STEP_UP_REQUIRED = "STEP_UP_REQUIRED",
  MAGIC_LINK_EXPIRED = "MAGIC_LINK_EXPIRED",
  SESSION_EXPIRED = "SESSION_EXPIRED",
  REFRESH_FAILED = "REFRESH_FAILED",
  /**
   * A test environment holds its limit of something. Unlike RATE_LIMITED,
   * waiting does not help: the ceiling is on stored rows, so room is made by
   * deleting or by moving to live.
   */
  TEST_QUOTA_EXCEEDED = "TEST_QUOTA_EXCEEDED",
  SERVER_ERROR = "SERVER_ERROR",
  UNKNOWN = "UNKNOWN",
}

/**
 * The engine's `code` field, translated.
 *
 * Every error body the engine sends carries a stable snake_case `code`, and it
 * is the only part of the body meant to be branched on — the prose beside it may
 * be reworded at any time. Several of these collapse onto one client code
 * deliberately: a page has nothing different to do about `forbidden` than about
 * `tenant_admin_required`, and pretending otherwise would push the engine's
 * permission model into every consumer.
 *
 * A code missing from this table falls back to the HTTP status, which is why
 * adding an engine code does not break an older client — it just loses the
 * distinction until the table catches up.
 */
const ENGINE_ERROR_CODES: Readonly<Record<string, AuthnErrorCode>> = {
  invalid_request_body: AuthnErrorCode.INVALID_PARAMS,
  validation_failed: AuthnErrorCode.VALIDATION_ERROR,
  missing_parameter: AuthnErrorCode.INVALID_PARAMS,

  unauthorized: AuthnErrorCode.UNAUTHORIZED,
  invalid_credentials: AuthnErrorCode.INVALID_CREDENTIALS,
  session_expired: AuthnErrorCode.SESSION_EXPIRED,
  invalid_token: AuthnErrorCode.UNAUTHORIZED,
  email_verification_required: AuthnErrorCode.EMAIL_VERIFICATION_REQUIRED,
  // Both name a credential the request has to carry and did not. `totp_required` is
  // the account-deletion route's spelling of the same refusal; the engine picks the
  // factor either way, so a client has one case to handle rather than two.
  step_up_required: AuthnErrorCode.STEP_UP_REQUIRED,
  totp_required: AuthnErrorCode.STEP_UP_REQUIRED,
  magic_link_expired: AuthnErrorCode.MAGIC_LINK_EXPIRED,
  // A challenge is issued as a 200 carrying `mfaRequired`, so this arrives only
  // when a request that needed a completed challenge was made without one.
  mfa_required: AuthnErrorCode.UNAUTHORIZED,
  invalid_mfa_code: AuthnErrorCode.INVALID_MFA_CODE,
  account_disabled: AuthnErrorCode.ACCOUNT_DISABLED,

  forbidden: AuthnErrorCode.FORBIDDEN,
  insufficient_permissions: AuthnErrorCode.FORBIDDEN,
  tenant_admin_required: AuthnErrorCode.FORBIDDEN,
  impersonation_blocked: AuthnErrorCode.FORBIDDEN,
  live_key_required: AuthnErrorCode.FORBIDDEN,

  // Both mean the credential is individually valid but does not belong with the
  // rest of the request. Nothing the end user did causes either, so they read as
  // a misconfigured client rather than a refusal to relay.
  tenant_mismatch: AuthnErrorCode.INVALID_CONFIG,
  origin_not_allowed: AuthnErrorCode.INVALID_CONFIG,

  not_found: AuthnErrorCode.NOT_FOUND,
  already_exists: AuthnErrorCode.EMAIL_ALREADY_EXISTS,
  conflict: AuthnErrorCode.CONFLICT,

  rate_limited: AuthnErrorCode.RATE_LIMITED,
  service_unavailable: AuthnErrorCode.SERVER_ERROR,
  test_quota_exceeded: AuthnErrorCode.TEST_QUOTA_EXCEEDED,

  internal_error: AuthnErrorCode.SERVER_ERROR,
};

/**
 * Pulls everything the body says beyond its two contract fields.
 *
 * The engine reports supporting facts — `missing_criteria` for a rejected
 * password, `retry_after` for a throttle — as siblings of `error` and `code`
 * rather than under a `details` key, so reading only `details` silently drops
 * them and leaves a form saying "your password does not meet policy" without
 * being able to say which part. Both shapes are collected, with a nested
 * `details` object flattened in.
 */
function extractDetails(body: Record<string, unknown>): Record<string, unknown> | undefined {
  const details: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(body)) {
    if (key === "error" || key === "code" || key === "message" || key === "details") continue;
    details[key] = value;
  }

  const nested = body["details"];
  if (nested && typeof nested === "object" && !Array.isArray(nested)) {
    Object.assign(details, nested as Record<string, unknown>);
  }

  return Object.keys(details).length > 0 ? details : undefined;
}

export interface AuthnErrorOptions {
  message: string;
  code: AuthnErrorCode;
  statusCode?: number;
  requestId?: string;
  details?: Record<string, unknown>;
  cause?: unknown;
}

export class AuthnError extends Error {
  readonly code: AuthnErrorCode;
  readonly statusCode: number;
  readonly requestId?: string;
  readonly details?: Record<string, unknown>;
  readonly isRetryable: boolean;
  readonly timestamp: string;

  constructor(options: AuthnErrorOptions) {
    super(options.message, { cause: options.cause });
    this.name = "AuthnError";
    this.code = options.code;
    this.statusCode = options.statusCode ?? 0;
    this.requestId = options.requestId;
    this.details = options.details;
    this.timestamp = new Date().toISOString();

    this.isRetryable =
      options.code === AuthnErrorCode.NETWORK_ERROR ||
      options.code === AuthnErrorCode.TIMEOUT ||
      options.statusCode === 429 ||
      (options.statusCode ?? 0) >= 500;

    Object.setPrototypeOf(this, AuthnError.prototype);
  }

  static network(message = "Network unreachable.", cause?: unknown): AuthnError {
    return new AuthnError({
      message,
      code: AuthnErrorCode.NETWORK_ERROR,
      cause,
    });
  }

  static networkError(cause?: unknown): AuthnError {
    return new AuthnError({
      message: cause instanceof Error ? cause.message : "Network request failed",
      code: AuthnErrorCode.NETWORK_ERROR,
      cause,
    });
  }

  static timeout(pathOrMs: string | number, ms?: number): AuthnError {
    const duration = typeof pathOrMs === "number" ? pathOrMs : ms ?? 10000;
    const path = typeof pathOrMs === "string" ? pathOrMs : "";
    return new AuthnError({
      message: `Request to "${path}" timed out after ${duration}ms.`,
      code: AuthnErrorCode.TIMEOUT,
    });
  }

  /**
   * cancelled reports a request abandoned because its client was destroyed.
   *
   * It is deliberately not retryable. The generic retry path treats an
   * unanswered request as worth another attempt, which is right for a flaky
   * network and wrong here — the caller that wanted the answer is gone, so a
   * retry only keeps a dead client making requests.
   */
  static cancelled(path: string): AuthnError {
    return new AuthnError({
      message: `Request to "${path}" was cancelled because the client was destroyed.`,
      code: AuthnErrorCode.CANCELLED,
    });
  }

  static invalidConfig(paramName: string, message: string): AuthnError {
    return new AuthnError({
      message: `Invalid configuration for "${paramName}": ${message}`,
      code: AuthnErrorCode.INVALID_CONFIG,
      details: { parameter: paramName },
    });
  }

  static validation(fieldName: string, message: string): AuthnError {
    return new AuthnError({
      message: `Invalid parameter "${fieldName}": ${message}`,
      code: AuthnErrorCode.INVALID_PARAMS,
      details: { field: fieldName },
    });
  }

  /**
   * fromResponse builds an error from a server error body.
   *
   * The body's `code` wins over the HTTP status whenever it is recognised,
   * because a status is a category and the code is the specific fact: a 400
   * covers both a malformed body and a password the policy rejected, and only
   * one of those is worth pointing a form field at. The status ladder stays as
   * the fallback for whatever sits between the client and the engine — a proxy
   * or load balancer answers with no code at all.
   */
  static fromResponse(
    status: number,
    body: Record<string, unknown>,
    requestId?: string,
  ): AuthnError {
    const rawMessage = (body["error"] || body["message"] || "HTTP error " + status) as string;
    const rawCode = (body["code"] as string) || "";

    let code = AuthnErrorCode.UNKNOWN;
    if (status === 400) code = AuthnErrorCode.INVALID_PARAMS;
    else if (status === 401) code = AuthnErrorCode.UNAUTHORIZED;
    else if (status === 403) code = AuthnErrorCode.FORBIDDEN;
    else if (status === 404) code = AuthnErrorCode.NOT_FOUND;
    else if (status === 409) code = AuthnErrorCode.CONFLICT;
    else if (status === 422) code = AuthnErrorCode.VALIDATION_ERROR;
    else if (status === 429) code = AuthnErrorCode.RATE_LIMITED;
    else if (status >= 500) code = AuthnErrorCode.SERVER_ERROR;

    const mapped = ENGINE_ERROR_CODES[rawCode];
    if (mapped) {
      code = mapped;
    } else if (rawCode in AuthnErrorCode) {
      // An error that has already been through this class once, re-serialized by
      // an intermediary from toJSON(). Its code is a client code, not a wire one.
      code = rawCode as AuthnErrorCode;
    }

    return new AuthnError({
      message: rawMessage,
      code,
      statusCode: status,
      requestId,
      details: extractDetails(body),
    });
  }

  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      requestId: this.requestId,
      details: this.details,
      isRetryable: this.isRetryable,
      timestamp: this.timestamp,
    };
  }
}

export function isAuthnError(err: unknown): err is AuthnError {
  return err instanceof AuthnError;
}
