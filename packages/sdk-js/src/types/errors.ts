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
  INVALID_CREDENTIALS = "INVALID_CREDENTIALS",
  EMAIL_VERIFICATION_REQUIRED = "EMAIL_VERIFICATION_REQUIRED",
  MAGIC_LINK_EXPIRED = "MAGIC_LINK_EXPIRED",
  SESSION_EXPIRED = "SESSION_EXPIRED",
  REFRESH_FAILED = "REFRESH_FAILED",
  SERVER_ERROR = "SERVER_ERROR",
  UNKNOWN = "UNKNOWN",
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

  static fromResponse(
    status: number,
    body: Record<string, unknown>,
    requestId?: string,
  ): AuthnError {
    const rawMessage = (body["error"] || body["message"] || "HTTP error " + status) as string;
    const rawCode = (body["code"] as string) || "";

    let code = AuthnErrorCode.UNKNOWN;
    if (status === 401) code = AuthnErrorCode.UNAUTHORIZED;
    else if (status === 403) code = AuthnErrorCode.FORBIDDEN;
    else if (status === 404) code = AuthnErrorCode.NOT_FOUND;
    else if (status === 409) code = AuthnErrorCode.EMAIL_ALREADY_EXISTS;
    else if (status === 422) code = AuthnErrorCode.VALIDATION_ERROR;
    else if (status === 429) code = AuthnErrorCode.RATE_LIMITED;
    else if (status >= 500) code = AuthnErrorCode.SERVER_ERROR;

    if (rawCode in AuthnErrorCode) {
      code = rawCode as AuthnErrorCode;
    }

    return new AuthnError({
      message: rawMessage,
      code,
      statusCode: status,
      requestId,
      details: (body["details"] as Record<string, unknown>) || undefined,
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
