/**
 * @authn/js — HTTP Client
 *
 * Internal fetch wrapper responsible for:
 * - Automatic timeout via AbortController
 * - Retry with exponential backoff on 429 and 503
 * - Header injection (publishable key, content type)
 * - JSON response parsing with error wrapping
 * - Rate limit Retry-After header parsing
 * - Request ID extraction for support correlation
 *
 * NOT exported to consumers.
 *
 * @internal
 */

import type { AuthnLogger } from "./types";
import { AuthnError, AuthnErrorCode } from "./types";

const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000;

export interface HttpClientConfig {
  baseUrl: string;
  publishableKey: string;
  timeout: number;
  logger: AuthnLogger;
  customFetch?: typeof globalThis.fetch;
}

export interface HttpResponse<T> {
  data: T;
  status: number;
  requestId?: string;
}

export class HttpClient {
  private readonly baseUrl: string;
  private readonly publishableKey: string;
  private readonly timeout: number;
  private readonly logger: AuthnLogger;
  private readonly fetchFn: typeof globalThis.fetch;

  constructor(config: HttpClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.publishableKey = config.publishableKey;
    this.timeout = config.timeout;
    this.logger = config.logger;
    this.fetchFn = config.customFetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Send a POST request with JSON body.
   * @throws {AuthnError} On network failure, timeout, or non-2xx response.
   */
  async post<T>(
    path: string,
    body?: Record<string, unknown>,
  ): Promise<HttpResponse<T>> {
    return this.request<T>("POST", path, body);
  }

  /**
   * Send a GET request with optional query parameters.
   * @throws {AuthnError} On network failure, timeout, or non-2xx response.
   */
  async get<T>(
    path: string,
    params?: Record<string, string>,
  ): Promise<HttpResponse<T>> {
    let url = path;
    if (params) {
      const searchParams = new URLSearchParams(params);
      const qs = searchParams.toString();
      if (qs) url = `${path}?${qs}`;
    }
    return this.request<T>("GET", url);
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    attempt = 0,
  ): Promise<HttpResponse<T>> {
    const url = `${this.baseUrl}${path}`;

    this.logger.debug(`${method} ${path}`, { attempt });

    // Build AbortController for timeout
    let controller: AbortController | undefined;
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    try {
      controller = new AbortController();
      timeoutId = setTimeout(() => controller!.abort(), this.timeout);
    } catch {
      // AbortController not available in very old environments — proceed without timeout
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Authn-Publishable-Key": this.publishableKey,
    };

    let response: Response;
    try {
      response = await this.fetchFn(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        credentials: "include",
        signal: controller?.signal,
      });
    } catch (err: unknown) {
      if (timeoutId !== undefined) clearTimeout(timeoutId);

      // Distinguish timeout from network error
      if (
        err instanceof DOMException &&
        err.name === "AbortError"
      ) {
        throw AuthnError.timeout(path, this.timeout);
      }

      // True network failure — check if retryable
      if (attempt < MAX_RETRIES) {
        const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
        this.logger.warn(`Network error on ${method} ${path}, retrying in ${delay}ms…`, {
          attempt,
          error: err instanceof Error ? err.message : String(err),
        });
        await sleep(delay);
        return this.request<T>(method, path, body, attempt + 1);
      }

      throw AuthnError.networkError(err);
    } finally {
      if (timeoutId !== undefined) clearTimeout(timeoutId);
    }

    const requestId = response.headers.get("X-Request-Id") ?? undefined;

    // Handle 429 / 503 retries
    if (
      (response.status === 429 || response.status === 503) &&
      attempt < MAX_RETRIES
    ) {
      const retryAfter = parseRetryAfter(response.headers.get("Retry-After"));
      const delay = retryAfter ?? INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);

      this.logger.warn(
        `${response.status} on ${method} ${path}, retrying in ${delay}ms…`,
        { attempt, retryAfter, requestId },
      );
      await sleep(delay);
      return this.request<T>(method, path, body, attempt + 1);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return {
        data: {} as T,
        status: 204,
        requestId,
      };
    }

    // Parse response body
    let parsed: unknown;
    try {
      const text = await response.text();
      parsed = text ? JSON.parse(text) : {};
    } catch {
      // Response body is not JSON (e.g., 502 HTML from a reverse proxy)
      if (!response.ok) {
        throw new AuthnError({
          message: `Server returned ${response.status} with non-JSON body. This usually means a proxy or load balancer error — try again shortly.`,
          code:
            response.status >= 500
              ? AuthnErrorCode.SERVER_ERROR
              : AuthnErrorCode.UNKNOWN,
          statusCode: response.status,
          requestId,
        });
      }
      parsed = {};
    }

    // Non-2xx → throw structured error
    if (!response.ok) {
      const errorBody =
        typeof parsed === "object" && parsed !== null
          ? (parsed as Record<string, unknown>)
          : { message: String(parsed) };

      throw AuthnError.fromResponse(response.status, errorBody, requestId);
    }

    this.logger.debug(`${method} ${path} → ${response.status}`, { requestId });

    return {
      data: parsed as T,
      status: response.status,
      requestId,
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Parse the HTTP `Retry-After` header.
 * Supports both delta-seconds and HTTP-date formats.
 * Returns milliseconds to wait, or `undefined` if unparseable.
 */
function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;

  // Try as integer seconds first
  const seconds = parseInt(header, 10);
  if (!isNaN(seconds) && seconds > 0) {
    return seconds * 1000;
  }

  // Try as HTTP-date
  const date = new Date(header);
  if (!isNaN(date.getTime())) {
    const delta = date.getTime() - Date.now();
    return delta > 0 ? delta : 0;
  }

  return undefined;
}
