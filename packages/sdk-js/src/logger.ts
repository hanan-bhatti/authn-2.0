/**
 * @authn/js — Logger
 *
 * Default logging implementations. The SDK uses these to surface
 * developer warnings, debug traces, and error reports without
 * cluttering production builds.
 *
 * @internal
 */

import type { AuthnLogger } from "./types";

/** Silent logger — all methods are no-ops. Used in production. */
const NOOP_LOGGER: AuthnLogger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/** Formatted console logger with `[authn]` prefix. Used in development. */
const CONSOLE_LOGGER: AuthnLogger = {
  debug(message: string, data?: Record<string, unknown>) {
    console.debug(`[authn] ${message}`, data ?? "");
  },
  info(message: string, data?: Record<string, unknown>) {
    console.info(`[authn] ${message}`, data ?? "");
  },
  warn(message: string, data?: Record<string, unknown>) {
    console.warn(`[authn] ⚠ ${message}`, data ?? "");
  },
  error(message: string, data?: Record<string, unknown>) {
    console.error(`[authn] ✖ ${message}`, data ?? "");
  },
};

/**
 * Detect the runtime environment and return an appropriate default logger.
 *
 * - If `process.env.NODE_ENV === "production"` → silent
 * - If `console.debug` is available → console logger
 * - Otherwise → silent
 */
export function createDefaultLogger(): AuthnLogger {
  try {
    if (
      typeof process !== "undefined" &&
      typeof process.env !== "undefined" &&
      process.env["NODE_ENV"] === "production"
    ) {
      return NOOP_LOGGER;
    }
  } catch {
    // process may throw in some edge environments (e.g. Cloudflare Workers)
  }

  if (typeof console !== "undefined" && typeof console.debug === "function") {
    return CONSOLE_LOGGER;
  }

  return NOOP_LOGGER;
}
