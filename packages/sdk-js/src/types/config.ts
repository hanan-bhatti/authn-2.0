/**
 * @authn/js — Client Configuration Types
 *
 * @packageDocumentation
 */

import type { AuthnError } from "./errors";

export interface AuthnLogger {
  debug(message: string, data?: Record<string, unknown>): void;
  info(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
}

export interface AuthnClientConfig {
  publishableKey?: string;
  endpoint?: string;
  tenantId?: string;
  environment?: "test" | "live";
  timeout?: number;
  autoRefresh?: boolean;
  onError?: (error: AuthnError) => void;
  logger?: AuthnLogger;
  fetch?: typeof globalThis.fetch;
}
