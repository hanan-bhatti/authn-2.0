/**
 * @authn/js — HTTP Client
 *
 * Internal fetch wrapper.
 *
 * @internal
 */

import type { AuthnLogger, SessionResult } from "../types";
import { AuthnError, AuthnErrorCode } from "../types";

const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000;

export interface HttpClientConfig {
  baseUrl: string;
  publishableKey: string;
  timeout: number;
  logger: AuthnLogger;
  customFetch?: typeof globalThis.fetch;
  customHeaders?: Record<string, string>;
  getAccessToken?: () => string | null;
  onRefreshToken?: () => Promise<SessionResult>;
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
  private readonly getAccessToken?: () => string | null;
  private readonly onRefreshToken?: () => Promise<SessionResult>;

  private readonly customHeaders?: Record<string, string>;

  constructor(config: HttpClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.publishableKey = config.publishableKey;
    this.timeout = config.timeout;
    this.logger = config.logger;
    this.fetchFn = config.customFetch ?? globalThis.fetch.bind(globalThis);
    this.customHeaders = config.customHeaders;
    this.getAccessToken = config.getAccessToken;
    this.onRefreshToken = config.onRefreshToken;
  }

  async post<T>(
    path: string,
    body?: Record<string, unknown>,
    extraHeaders?: Record<string, string>,
  ): Promise<HttpResponse<T>> {
    return this.request<T>("POST", path, body, 0, false, extraHeaders);
  }

  async get<T>(
    path: string,
    params?: Record<string, string>,
  ): Promise<HttpResponse<T>> {
    return this.request<T>("GET", withQuery(path, params));
  }

  async patch<T>(
    path: string,
    body?: Record<string, unknown>,
  ): Promise<HttpResponse<T>> {
    return this.request<T>("PATCH", path, body);
  }

  async put<T>(
    path: string,
    body?: Record<string, unknown>,
  ): Promise<HttpResponse<T>> {
    return this.request<T>("PUT", path, body);
  }

  async del<T>(
    path: string,
    body?: Record<string, unknown>,
    params?: Record<string, string>,
  ): Promise<HttpResponse<T>> {
    return this.request<T>("DELETE", withQuery(path, params), body);
  }

  async postRaw<T>(
    path: string,
    rawBody: unknown,
    params?: Record<string, string>,
  ): Promise<HttpResponse<T>> {
    return this.request<T>("POST", withQuery(path, params), rawBody as never);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    attempt = 0,
    isRetryAfterRefresh = false,
    extraHeaders?: Record<string, string>,
  ): Promise<HttpResponse<T>> {
    const url = `${this.baseUrl}${path}`;

    this.logger.debug(`${method} ${path}`, { attempt, isRetryAfterRefresh });

    let controller: AbortController | undefined;
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    try {
      controller = new AbortController();
      timeoutId = setTimeout(() => controller!.abort(), this.timeout);
    } catch {
      // AbortController not supported
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Authn-Publishable-Key": this.publishableKey,
      "X-Authn-Client-Type": "web",
    };

    if (this.publishableKey && this.publishableKey.startsWith("sk_")) {
      headers["Authorization"] = `Bearer ${this.publishableKey}`;
      headers["X-Authn-Secret-Key"] = this.publishableKey;
    }

    const accessToken = this.getAccessToken?.();
    if (accessToken) {
      headers["Authorization"] = `Bearer ${accessToken}`;
    }

    if (extraHeaders) {
      Object.assign(headers, extraHeaders);
    }
    if (this.customHeaders) {
      Object.assign(headers, this.customHeaders);
    }

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

      if (
        typeof DOMException !== "undefined" &&
        err instanceof DOMException &&
        err.name === "AbortError"
      ) {
        throw AuthnError.timeout(path, this.timeout);
      }

      if (attempt < MAX_RETRIES) {
        const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
        this.logger.warn(`Network error on ${method} ${path}, retrying in ${delay}ms…`, {
          attempt,
          error: err instanceof Error ? err.message : String(err),
        });
        await sleep(delay);
        return this.request<T>(method, path, body, attempt + 1, isRetryAfterRefresh);
      }

      throw AuthnError.networkError(err);
    } finally {
      if (timeoutId !== undefined) clearTimeout(timeoutId);
    }

    const requestId = response.headers.get("X-Request-Id") ?? undefined;

    // Surface degraded-mode signal so callers and loggers can observe it (Finding 2.2)
    if (response.headers.get("X-Authn-Degraded-Mode") === "true") {
      this.logger.warn(`Server is operating in degraded mode`, {
        path,
        requestId,
        method,
      });
    }

    const isRefreshEndpoint =
      path.endsWith("/v1/oauth/token") ||
      path.endsWith("/v1/client/auth/refresh");

    if (
      response.status === 401 &&
      accessToken &&
      !isRetryAfterRefresh &&
      !isRefreshEndpoint &&
      this.onRefreshToken
    ) {
      this.logger.warn(
        `401 Unauthorized on authenticated request ${method} ${path} — attempting silent token refresh…`,
        { requestId },
      );

      const refreshResult = await this.onRefreshToken();

      if (refreshResult.ok) {
        this.logger.info(
          `Token refresh succeeded — retrying original request ${method} ${path}`,
        );
        return this.request<T>(method, path, body, 0, true);
      }

      this.logger.error(
        `Token refresh failed after 401 on ${method} ${path} — surfacing error without retry loop`,
      );
      let parsedErrBody: Record<string, unknown> = {};
      try {
        const text = await response.text();
        if (text) parsedErrBody = JSON.parse(text);
      } catch {
        // ignore JSON parse
      }
      throw AuthnError.fromResponse(401, parsedErrBody, requestId);
    }

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
      return this.request<T>(method, path, body, attempt + 1, isRetryAfterRefresh);
    }

    if (response.status === 204) {
      return {
        data: {} as T,
        status: 204,
        requestId,
      };
    }

    let parsed: unknown;
    try {
      const text = await response.text();
      parsed = text ? JSON.parse(text) : {};
    } catch {
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function withQuery(path: string, params?: Record<string, string | undefined>): string {
  if (!params) return path;

  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      searchParams.append(key, value);
    }
  }

  const qs = searchParams.toString();
  if (!qs) return path;

  return path.includes("?") ? `${path}&${qs}` : `${path}?${qs}`;
}

function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;

  const seconds = parseInt(header, 10);
  if (!isNaN(seconds) && seconds > 0) {
    return seconds * 1000;
  }

  const date = new Date(header);
  if (!isNaN(date.getTime())) {
    const delta = date.getTime() - Date.now();
    return delta > 0 ? delta : 0;
  }

  return undefined;
}
