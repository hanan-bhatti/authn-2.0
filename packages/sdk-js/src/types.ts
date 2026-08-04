/**
 * @authn/js — Type Definitions
 *
 * All public TypeScript types for the Authn SDK.
 * Every type mirrors the Go Auth Engine's DTOs exactly.
 *
 * @packageDocumentation
 */

// ---------------------------------------------------------------------------
// Error Codes
// ---------------------------------------------------------------------------

/** Structured error codes returned by every failed SDK operation. */
export enum AuthnErrorCode {
  /** Network unreachable or fetch failed before reaching the server. */
  NETWORK_ERROR = "NETWORK_ERROR",
  /** Request exceeded the configured timeout (default: 10 000 ms). */
  TIMEOUT = "TIMEOUT",
  /** SDK was initialized with invalid configuration values. */
  INVALID_CONFIG = "INVALID_CONFIG",
  /** Method was called with invalid or missing parameters. */
  INVALID_PARAMS = "INVALID_PARAMS",
  /** Publishable key format is wrong (expected `pk_test_…` or `pk_live_…`). */
  INVALID_PUBLISHABLE_KEY = "INVALID_PUBLISHABLE_KEY",
  /** Server returned 401 — token expired or missing. */
  UNAUTHORIZED = "UNAUTHORIZED",
  /** Server returned 403 — action not allowed (e.g. hard-blocked unverified user). */
  FORBIDDEN = "FORBIDDEN",
  /** Server returned 404. */
  NOT_FOUND = "NOT_FOUND",
  /** Server returned 429 — too many requests. */
  RATE_LIMITED = "RATE_LIMITED",
  /** Server returned 422 or field-level validation failed. */
  VALIDATION_ERROR = "VALIDATION_ERROR",
  /** Sign-up attempted with an email that already has an account. */
  EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS",
  /** Login failed — wrong email or password. */
  INVALID_CREDENTIALS = "INVALID_CREDENTIALS",
  /** Login succeeded but account requires email verification first (hard block). */
  EMAIL_VERIFICATION_REQUIRED = "EMAIL_VERIFICATION_REQUIRED",
  /** Magic link token has expired or was already used. */
  MAGIC_LINK_EXPIRED = "MAGIC_LINK_EXPIRED",
  /** Access token has expired and could not be silently refreshed. */
  SESSION_EXPIRED = "SESSION_EXPIRED",
  /** Silent token refresh failed — user must re-authenticate. */
  REFRESH_FAILED = "REFRESH_FAILED",
  /** Server returned 5xx. */
  SERVER_ERROR = "SERVER_ERROR",
  /** Catch-all for unexpected error shapes. */
  UNKNOWN = "UNKNOWN",
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

/** Pluggable logger interface. Implement to route SDK logs to your observability stack. */
export interface AuthnLogger {
  debug(message: string, data?: Record<string, unknown>): void;
  info(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
}

// ---------------------------------------------------------------------------
// Client Configuration
// ---------------------------------------------------------------------------

/**
 * Configuration object passed to `new AuthnClient(config)`.
 *
 * Only `publishableKey` is required — everything else has safe defaults.
 *
 * @example
 * ```ts
 * const authn = new AuthnClient({
 *   publishableKey: "pk_test_abc123def456ghi789jkl012mno345pq",
 *   endpoint: "http://localhost:8080",
 * });
 * ```
 */
export interface AuthnClientConfig {
  /**
   * Your project's publishable key from the Authn Console.
   * Format: `pk_test_<32+ alphanumeric chars>` or `pk_live_<32+ chars>`.
   */
  publishableKey: string;

  /**
   * Base URL of the Authn Engine API.
   * @default "https://api.authn.com"
   */
  endpoint?: string;

  /**
   * Default tenant ID prepended to all requests.
   * Can be overridden per-method via `params.tenantId`.
   */
  tenantId?: string;

  /**
   * Environment inferred from `publishableKey` prefix (`pk_test_` → `"test"`, `pk_live_` → `"live"`).
   * Explicit value here overrides the inference.
   */
  environment?: "test" | "live";

  /**
   * HTTP request timeout in milliseconds.
   * @default 10000
   */
  timeout?: number;

  /**
   * Whether to silently refresh the JWT access token before it expires.
   * The SDK schedules a refresh 60 seconds before `expiresAt`.
   * @default true
   */
  autoRefresh?: boolean;

  /**
   * Global error callback invoked on every failed operation.
   * Useful for centralized error reporting (e.g. Sentry, LogRocket).
   */
  onError?: (error: AuthnError) => void;

  /** Custom logger. Defaults to console in development, silent in production. */
  logger?: AuthnLogger;

  /**
   * Custom `fetch` implementation for SSR / Node.js / Cloudflare Workers.
   * Falls back to `globalThis.fetch`.
   */
  fetch?: typeof globalThis.fetch;
}

// ---------------------------------------------------------------------------
// User & Session (mirrors Go DTOs)
// ---------------------------------------------------------------------------

/**
 * Public user profile. Matches the Go `UserDTO` struct in `handler.go`.
 * All fields are read-only — mutation happens server-side via API calls.
 */
export interface AuthnUser {
  /** Unique user identifier, e.g. `usr_1a2b3c`. */
  id: string;
  /** User's primary email address. */
  email: string;
  /** Whether the user has completed email verification. */
  emailVerified: boolean;
  /** Display name (optional — may not be set). */
  name?: string;
  /** Account status: `active`, `suspended`, or `banned`. */
  status: "active" | "suspended" | "banned";
  /** ISO 8601 timestamp of account creation. */
  createdAt: string;
}

/**
 * Active authentication session containing the JWT access token and user profile.
 */
export interface AuthnSession {
  /** Short-lived JWT access token (typically 15 min TTL). */
  accessToken: string;
  /**
   * Refresh token — **only present for native mobile clients** (`clientType: "native"`).
   * Web clients use HttpOnly SameSite cookies managed automatically by the server.
   */
  refreshToken?: string;
  /** Unix timestamp (seconds) when `accessToken` expires. */
  expiresAt: number;
  /** The authenticated user's public profile. */
  user: AuthnUser;
}

// ---------------------------------------------------------------------------
// Policy Warning
// ---------------------------------------------------------------------------

/**
 * Advisory notices returned alongside a successful login when the account
 * has pending compliance requirements.
 *
 * These are "soft gate" warnings — the session was still issued,
 * but the frontend should prompt the user to resolve them.
 */
export interface PolicyWarning {
  /** User's current password doesn't meet the updated password policy. */
  requiresPasswordUpgrade?: boolean;
  /** User hasn't verified their email and the admin has soft-gate enabled. */
  requiresEmailVerification?: boolean;
  /** Specific password criteria the current password is missing. */
  missingCriteria?: string[];
}

// ---------------------------------------------------------------------------
// Discriminated Result Types
// ---------------------------------------------------------------------------

/**
 * Result of `signUp()`, `login()`, or `verifyMagicLink()`.
 *
 * Always check `result.ok` before accessing `.session`:
 * ```ts
 * const result = await authn.login({ email, password });
 * if (result.ok) {
 *   console.log(result.session.user.email);
 * } else {
 *   console.error(result.error.message);
 * }
 * ```
 */
export type AuthResult =
  | { ok: true; session: AuthnSession; policyWarning?: PolicyWarning }
  | { ok: false; error: AuthnError };

/**
 * Result of `refreshSession()`.
 */
export type SessionResult =
  | { ok: true; session: AuthnSession }
  | { ok: false; error: AuthnError };

/**
 * Result of operations that don't return data (e.g. `sendMagicLink()`, `signOut()`).
 */
export type VoidResult =
  | { ok: true; message?: string }
  | { ok: false; error: AuthnError };

// ---------------------------------------------------------------------------
// Method Parameters
// ---------------------------------------------------------------------------

/** Parameters for `authn.signUp()`. */
export interface SignUpParams {
  email: string;
  password: string;
  name?: string;
  /** Override the default tenant. */
  tenantId?: string;
  /** Override the default environment. */
  environment?: "test" | "live";
}

/** Parameters for `authn.login()`. */
export interface LoginParams {
  email: string;
  password: string;
  tenantId?: string;
  environment?: "test" | "live";
}

/** Parameters for `authn.sendMagicLink()`. */
export interface MagicLinkParams {
  email: string;
  /** Display name for auto-provisioned accounts. */
  name?: string;
  tenantId?: string;
  environment?: "test" | "live";
}

/** Parameters for `authn.verifyMagicLink()`. */
export interface VerifyMagicLinkParams {
  token: string;
  tenantId?: string;
  environment?: "test" | "live";
}

/** Parameters for `authn.verifyEmail()`. */
export interface VerifyEmailParams {
  token: string;
}

/** Parameters for `authn.resendVerification()`. */
export interface ResendVerificationParams {
  email: string;
  tenantId?: string;
  environment?: "test" | "live";
}

// ---------------------------------------------------------------------------
// Auth State Listener
// ---------------------------------------------------------------------------

/**
 * Callback invoked whenever the authentication state changes.
 *
 * Triggers on:
 * - Initial subscription (immediate fire with current state)
 * - Successful login / sign-up
 * - Silent token refresh (user object may have updated fields)
 * - Silent refresh failure (both become `null`)
 * - Explicit sign-out
 */
export type AuthStateCallback = (
  user: AuthnUser | null,
  session: AuthnSession | null,
) => void;

// ---------------------------------------------------------------------------
// Error class (forward declaration for use in result types)
// ---------------------------------------------------------------------------

/**
 * Structured error thrown or returned by every SDK operation.
 *
 * Extends native `Error` with machine-readable `code`, HTTP `statusCode`,
 * optional `requestId` for server-side correlation, and `isRetryable` flag.
 */
export class AuthnError extends Error {
  /** Machine-readable error code from {@link AuthnErrorCode}. */
  readonly code: AuthnErrorCode;
  /** HTTP status code from the server response (0 for client-side errors). */
  readonly statusCode: number;
  /** Server-assigned request ID for support correlation. */
  readonly requestId?: string;
  /** Additional context from the server error response. */
  readonly details?: Record<string, unknown>;
  /** Whether this error is safe to retry (true for 429, 503, network errors). */
  readonly isRetryable: boolean;
  /** ISO 8601 timestamp of when the error occurred. */
  readonly timestamp: string;

  constructor(params: {
    message: string;
    code: AuthnErrorCode;
    statusCode?: number;
    requestId?: string;
    details?: Record<string, unknown>;
    cause?: unknown;
  }) {
    super(params.message, { cause: params.cause });
    this.name = "AuthnError";
    this.code = params.code;
    this.statusCode = params.statusCode ?? 0;
    this.requestId = params.requestId;
    this.details = params.details;
    this.timestamp = new Date().toISOString();

    this.isRetryable =
      this.code === AuthnErrorCode.NETWORK_ERROR ||
      this.code === AuthnErrorCode.TIMEOUT ||
      this.code === AuthnErrorCode.RATE_LIMITED ||
      this.statusCode === 503;
  }

  /** Create from a failed HTTP response and parsed body. */
  static fromResponse(
    status: number,
    body: Record<string, unknown>,
    requestId?: string,
  ): AuthnError {
    const message =
      typeof body["message"] === "string"
        ? body["message"]
        : typeof body["error"] === "string"
          ? body["error"]
          : `Request failed with status ${status}`;

    const code = mapHttpStatusToCode(status, body);

    return new AuthnError({
      message,
      code,
      statusCode: status,
      requestId,
      details: body,
    });
  }

  /** Create a network connectivity error. */
  static networkError(cause: unknown): AuthnError {
    return new AuthnError({
      message: "Network request failed. Check your internet connection and try again.",
      code: AuthnErrorCode.NETWORK_ERROR,
      cause,
    });
  }

  /** Create a request timeout error. */
  static timeout(url: string, timeoutMs: number): AuthnError {
    return new AuthnError({
      message: `Request to ${url} timed out after ${timeoutMs}ms. The server may be overloaded — try again shortly.`,
      code: AuthnErrorCode.TIMEOUT,
      details: { url, timeoutMs },
    });
  }

  /** Create a parameter validation error. */
  static validation(field: string, message: string): AuthnError {
    return new AuthnError({
      message: `Invalid parameter "${field}": ${message}`,
      code: AuthnErrorCode.INVALID_PARAMS,
      details: { field },
    });
  }

  /** Create a configuration error. */
  static invalidConfig(field: string, message: string): AuthnError {
    return new AuthnError({
      message: `Invalid configuration "${field}": ${message}`,
      code: AuthnErrorCode.INVALID_CONFIG,
      details: { field },
    });
  }
}

/**
 * Type guard to check if an unknown value is an `AuthnError`.
 *
 * @example
 * ```ts
 * try { await authn.login(params); }
 * catch (e) {
 *   if (isAuthnError(e) && e.code === AuthnErrorCode.RATE_LIMITED) { ... }
 * }
 * ```
 */
export function isAuthnError(value: unknown): value is AuthnError {
  return value instanceof AuthnError;
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

function mapHttpStatusToCode(
  status: number,
  body: Record<string, unknown>,
): AuthnErrorCode {
  // Check for specific error identifiers from the Go engine
  const serverCode = typeof body["code"] === "string" ? body["code"] : "";
  const serverMessage = typeof body["message"] === "string" ? body["message"] : "";
  const combined = `${serverCode} ${serverMessage}`.toLowerCase();

  if (combined.includes("email_already_exists") || combined.includes("already exists")) {
    return AuthnErrorCode.EMAIL_ALREADY_EXISTS;
  }
  if (combined.includes("invalid_credentials") || combined.includes("invalid password")) {
    return AuthnErrorCode.INVALID_CREDENTIALS;
  }
  if (combined.includes("email_verification_required")) {
    return AuthnErrorCode.EMAIL_VERIFICATION_REQUIRED;
  }
  if (combined.includes("magic_link_expired") || combined.includes("token expired")) {
    return AuthnErrorCode.MAGIC_LINK_EXPIRED;
  }

  switch (status) {
    case 401:
      return AuthnErrorCode.UNAUTHORIZED;
    case 403:
      return AuthnErrorCode.FORBIDDEN;
    case 404:
      return AuthnErrorCode.NOT_FOUND;
    case 422:
      return AuthnErrorCode.VALIDATION_ERROR;
    case 429:
      return AuthnErrorCode.RATE_LIMITED;
    default:
      return status >= 500
        ? AuthnErrorCode.SERVER_ERROR
        : AuthnErrorCode.UNKNOWN;
  }
}
