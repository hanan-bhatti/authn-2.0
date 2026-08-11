import type { AuthnLogger } from "../types";

export class DefaultLogger implements AuthnLogger {
  private enabled: boolean;

  constructor(enabled = false) {
    this.enabled = enabled;
  }

  debug(message: string, data?: Record<string, unknown>): void {
    if (this.enabled) {
      console.debug(`[authn] ${message}`, data ?? "");
    }
  }

  info(message: string, data?: Record<string, unknown>): void {
    if (this.enabled) {
      console.info(`[authn] ${message}`, data ?? "");
    }
  }

  warn(message: string, data?: Record<string, unknown>): void {
    if (this.enabled) {
      console.warn(`[authn] ${message}`, data ?? "");
    }
  }

  error(message: string, data?: Record<string, unknown>): void {
    if (this.enabled) {
      console.error(`[authn] ${message}`, data ?? "");
    }
  }
}
